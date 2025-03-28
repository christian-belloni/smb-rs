use crate::sync_helpers::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::{select, sync::oneshot};

use crate::{msg_handler::IncomingMessage, packets::netbios::NetBiosTcpMessage, Error};

use crate::connection::netbios_client::NetBiosClient;

use super::backend_trait::MultiWorkerBackend;
use super::base::MultiWorkerBase;

#[derive(Debug, Default)]
pub struct AsyncBackend {
    /// The loop handles for the workers.
    loop_handles: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,

    token: CancellationToken,
}

#[cfg(feature = "async")]
impl AsyncBackend {
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Internal message loop handler.
    async fn recv_loop(
        self: Arc<Self>,
        mut netbios_client: NetBiosClient,
        worker: Arc<MultiWorkerBase<Self>>,
    ) {
        log::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref
                .handle_next_recv(&mut netbios_client, &worker)
                .await
            {
                Ok(_) => {}
                Err(Error::NotConnected) => {
                    if self.is_cancelled() {
                        log::info!("Connection closed.");
                    } else {
                        log::error!("Connection closed.");
                    }
                    break;
                }
                Err(e) => {
                    log::error!("Error in worker loop: {}", e);
                }
            }
        }

        // Cleanup
        log::debug!("Cleaning up worker loop.");
        if let Ok(mut state) = worker.state.lock().await {
            for (_, tx) in state.awaiting.drain() {
                tx.send(Err(Error::NotConnected)).unwrap();
            }
        }
    }

    async fn send_loop(
        self: Arc<Self>,
        mut netbios_client: NetBiosClient,
        mut send_channel: mpsc::Receiver<NetBiosTcpMessage>,
        worker: Arc<MultiWorkerBase<Self>>,
    ) {
        log::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref
                .handle_next_send(&mut netbios_client, &mut send_channel, &worker)
                .await
            {
                Ok(_) => {}
                Err(Error::NotConnected) => {
                    if self.is_cancelled() {
                        log::info!("Connection closed.");
                    } else {
                        log::error!("Connection closed.");
                    }
                    break;
                }
                Err(e) => {
                    log::error!("Error in worker loop: {}", e);
                }
            }
        }

        send_channel.close();
    }

    /// Handles the next message in the receive loop:
    /// receives a message, transforms it, and sends it to the correct awaiting task.
    async fn handle_next_recv(
        self: &Self,
        netbios_client: &mut NetBiosClient,
        worker: &Arc<MultiWorkerBase<Self>>,
    ) -> crate::Result<()> {
        debug_assert!(netbios_client.can_read());
        select! {
            // Receive a message from the server.
            message = netbios_client.received_bytes() => {
                worker.loop_handle_incoming(message).await
            }
            // Cancel the loop.
            _ = self.token.cancelled() => {
                Err(Error::NotConnected)
            }
        }
    }

    /// Handles the next message in the send loop:
    /// sends a message to the server.
    async fn handle_next_send(
        self: &Self,
        netbios_client: &mut NetBiosClient,
        send_channel: &mut mpsc::Receiver<NetBiosTcpMessage>,
        worker: &Arc<MultiWorkerBase<Self>>,
    ) -> crate::Result<()> {
        debug_assert!(netbios_client.can_write());
        select! {
            // Send a message to the server.
            message = send_channel.recv() => {
                worker.loop_handle_outgoing(message, netbios_client).await
            },
            // Cancel the loop.
            _ = self.token.cancelled() => {
                Err(Error::NotConnected)
            }
        }
    }
}

#[cfg(feature = "async")]
impl MultiWorkerBackend for AsyncBackend {
    type SendMessage = NetBiosTcpMessage;

    type AwaitingNotifier = oneshot::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = oneshot::Receiver<crate::Result<IncomingMessage>>;

    async fn start(
        netbios_client: NetBiosClient,
        worker: Arc<MultiWorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>> {
        let backend: Arc<Self> = Default::default();
        let backend_clone = backend.clone();
        let (netbios_recv, netbios_send) = netbios_client.split()?;

        let recv_task = {
            let backend_clone = backend_clone.clone();
            let worker = worker.clone();
            tokio::spawn(async move { backend_clone.recv_loop(netbios_recv, worker).await })
        };

        let send_task = tokio::spawn(async move {
            backend_clone
                .send_loop(netbios_send, send_channel_recv, worker)
                .await
        });
        backend
            .loop_handles
            .lock()
            .await?
            .replace((recv_task, send_task));

        Ok(backend)
    }

    async fn stop(&self) -> crate::Result<()> {
        log::debug!("Stopping worker.");
        self.token.cancel();
        let loop_handles = self
            .loop_handles
            .lock()
            .await?
            .take()
            .ok_or(Error::NotConnected)?;
        loop_handles.0.await?;
        loop_handles.1.await?;
        Ok(())
    }
    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage {
        msg
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        oneshot::channel()
    }

    async fn wait_on_waiter(
        waiter: Self::AwaitingWaiter,
        timeout: Duration,
    ) -> crate::Result<IncomingMessage> {
        if timeout == Duration::ZERO {
            waiter.await.map_err(|_| {
                Error::MessageProcessingError("Failed to receive message.".to_string())
            })?
        } else {
            tokio::select! {
                msg = waiter => {
                    msg.map_err(|_| Error::MessageProcessingError("Failed to receive message.".to_string()))?
                },
                _ = tokio::time::sleep(timeout) => {
                    Err(Error::OperationTimeout("Waiting for message receive.".to_string(), timeout))
                }
            }
        }
    }

    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()> {
        tx.send(msg).map_err(|_| {
            Error::MessageProcessingError("Failed to send message to awaiting task.".to_string())
        })
    }

    fn make_send_channel_pair() -> (
        mpsc::Sender<Self::SendMessage>,
        mpsc::Receiver<Self::SendMessage>,
    ) {
        mpsc::channel(100)
    }
}
