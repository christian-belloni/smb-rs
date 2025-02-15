use crate::sync_helpers::*;
use maybe_async::*;
use std::{collections::HashMap, sync::Arc};
#[cfg(feature = "sync")]
use std::{sync::atomic::AtomicBool, time::Duration};
#[cfg(feature = "async")]
use tokio::{select, sync::oneshot};

use crate::{
    msg_handler::{IncomingMessage, OutgoingMessage, SendMessageResult},
    packets::netbios::NetBiosTcpMessage,
    session::SessionState,
    Error,
};

use super::{
    negotiation_state::NegotiateState, netbios_client::NetBiosClient, transformer::Transformer,
};

/// SMB2 connection worker.
///
/// This struct is responsible for handling the connection to the server,
/// sending netbios messages from SMB2 messages, and redirecting correct messages when received,
/// if using async, to the correct pending task.
/// One-per connection, hence takes ownership of [NetBiosClient] on [ConnectionWorker::start].
#[derive(Debug)]
pub struct ConnectionWorker {
    state: Mutex<WorkerAwaitState>,

    #[cfg(feature = "async")]
    /// The loop handle for the worker.
    loop_handle: Mutex<Option<JoinHandle<()>>>,
    #[cfg(feature = "sync")]
    /// The loops' handles for the worker.
    loop_handles: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,

    transformer: Transformer,

    /// A channel to send messages to the worker.
    #[cfg(feature = "async")]
    sender: mpsc::Sender<NetBiosTcpMessage>,
    /// A channel to send messages to the worker.
    #[cfg(feature = "sync")]
    sender: mpsc::Sender<Option<NetBiosTcpMessage>>,

    #[cfg(feature = "async")]
    token: CancellationToken,

    #[cfg(feature = "sync")]
    stopped: AtomicBool,
}

/// Holds state for the worker, regarding messages to be received.
#[derive(Debug, Default)]
struct WorkerAwaitState {
    /// Stores the awaiting tasks that are waiting for a specific message ID.
    #[cfg(feature = "async")]
    awaiting: HashMap<u64, oneshot::Sender<crate::Result<IncomingMessage>>>,
    #[cfg(feature = "sync")]
    awaiting: HashMap<u64, std::sync::mpsc::Sender<crate::Result<IncomingMessage>>>,
    /// Stores the pending messages, waiting to be receive()-d.
    pending: HashMap<u64, IncomingMessage>,
}

impl ConnectionWorker {
    /// Instantiates a new connection worker.
    #[cfg(feature = "async")]
    pub async fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>> {
        // Build the worker
        let (tx, rx) = mpsc::channel(32);
        let worker = Arc::new(ConnectionWorker {
            state: Mutex::new(WorkerAwaitState::default()),
            loop_handle: Mutex::new(None),
            transformer: Transformer::default(),
            sender: tx,
            token: CancellationToken::new(),
        });

        // Start the worker loop.
        let worker_clone = worker.clone();
        let handle = tokio::spawn(async move { worker_clone.loop_fn(netbios_client, rx).await });
        worker.loop_handle.lock().await?.replace(handle);

        Ok(worker)
    }

    #[cfg(feature = "sync")]
    pub fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>> {
        // Build the worker
        let (tx, rx) = mpsc::channel();
        let worker = Arc::new(ConnectionWorker {
            state: Mutex::new(WorkerAwaitState::default()),
            loop_handles: Mutex::new(None),
            transformer: Transformer::default(),
            sender: tx,
            stopped: AtomicBool::new(false),
        });

        // Start the worker loops - send and receive.
        let worker_clone1 = worker.clone();
        let worker_clone2 = worker.clone();
        let netbios_receive = netbios_client;
        let netbios_send = netbios_receive.try_clone()?;

        netbios_receive.set_read_timeout(Some(Duration::from_millis(100)))?;

        let handle1 = std::thread::spawn(move || worker_clone1.loop_receive(netbios_receive));
        let handle2 = std::thread::spawn(move || worker_clone2.loop_send(netbios_send, rx));
        worker
            .loop_handles
            .lock()
            .unwrap()
            .replace((handle1, handle2));

        Ok(worker)
    }

    #[cfg(feature = "async")]
    pub async fn stop(&self) -> crate::Result<()> {
        log::debug!("Stopping worker.");
        self.token.cancel();
        self.loop_handle
            .lock()
            .await?
            .take()
            .ok_or(Error::NotConnected)?
            .await?;
        Ok(())
    }

    #[cfg(feature = "sync")]
    pub fn stop(&self) -> crate::Result<()> {
        log::debug!("Stopping worker.");

        let handles = self
            .loop_handles
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::NotConnected)?;

        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // wake up the sender to stop the loop.
        self.sender.send(None).unwrap();

        // Join the threads.
        handles
            .0
            .join()
            .map_err(|_| Error::JoinError("Error stopping reciever".to_string()))?;

        handles
            .1
            .join()
            .map_err(|_| Error::JoinError("Error stopping sender".to_string()))?;

        Ok(())
    }

    #[maybe_async]
    pub async fn negotaite_complete(&self, neg_state: &NegotiateState) {
        self.transformer.negotiated(neg_state).await.unwrap();
    }

    #[maybe_async]
    pub async fn session_started(&self, session: Arc<Mutex<SessionState>>) -> crate::Result<()> {
        self.transformer.session_started(session).await
    }

    #[maybe_async]
    pub async fn session_ended(&self, session_id: u64) -> crate::Result<()> {
        self.transformer.session_ended(session_id).await
    }

    #[maybe_async]
    pub async fn send(self: &Self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let finalize_preauth_hash = msg.finalize_preauth_hash;
        let id = msg.message.header.message_id;
        let message = { self.transformer.tranform_outgoing(msg).await? };

        let hash = match finalize_preauth_hash {
            true => Some(self.transformer.finalize_preauth_hash().await?),
            false => None,
        };

        log::trace!(
            "Message with ID {} is passed to the worker for sending.",
            id
        );

        #[cfg(feature = "sync")]
        let message = Some(message);

        self.sender.send(message).await.map_err(|_| {
            Error::MessageProcessingError("Failed to send message to worker!".to_string())
        })?;

        Ok(SendMessageResult::new(id, hash.clone()))
    }

    /// Receive a message from the server.
    /// This is a user function that will wait for the message to be received.
    #[maybe_async]
    pub async fn receive(self: &Self, msg_id: u64) -> crate::Result<IncomingMessage> {
        // 1. Insert channel to wait for the message, or return the message if already received.
        let wait_for_receive = {
            let mut state = self.state.lock().await?;

            if self.is_cancelled() {
                log::trace!("Connection is closed, avoid receiving.");
                return Err(Error::NotConnected);
            }
            if state.pending.contains_key(&msg_id) {
                log::trace!(
                    "Message with ID {} is already received, remove from pending.",
                    msg_id
                );
                return Ok(state.pending.remove(&msg_id).unwrap());
            }

            log::trace!(
                "Message with ID {} is not received yet, insert channel and await.",
                msg_id
            );

            #[cfg(feature = "async")]
            let (tx, rx) = oneshot::channel();
            #[cfg(feature = "sync")]
            let (tx, rx) = mpsc::channel();

            state.awaiting.insert(msg_id, tx);
            rx
        };

        #[cfg(feature = "async")]
        let wait_result = wait_for_receive.await;
        #[cfg(feature = "sync")]
        let wait_result = wait_for_receive.recv();

        // Wait for the message to be received.
        Ok(wait_result.map_err(|_| {
            Error::MessageProcessingError("Failed to receive message from worker!".to_string())
        })??)
    }

    #[cfg(feature = "async")]
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    #[cfg(feature = "sync")]
    fn is_cancelled(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Internal message loop handler.
    #[cfg(feature = "async")]
    async fn loop_fn(
        self: Arc<Self>,
        mut netbios_client: NetBiosClient,
        mut rx: mpsc::Receiver<NetBiosTcpMessage>,
    ) {
        log::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref.handle_next_msg(&mut netbios_client, &mut rx).await {
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
        // TODO: Handle cleanup recursively.
        log::debug!("Cleaning up worker loop.");
        rx.close();
        if let Ok(mut state) = self_ref.state.lock().await {
            for (_, tx) in state.awaiting.drain() {
                tx.send(Err(Error::NotConnected)).unwrap();
            }
        }
    }

    /// Handles the next message in the loop:
    /// - receives a message, transforms it, and sends it to the correct awaiting task.
    /// - sends a message to the server.
    #[cfg(feature = "async")]
    async fn handle_next_msg(
        self: &Self,
        netbios_client: &mut NetBiosClient,
        send_channel: &mut mpsc::Receiver<NetBiosTcpMessage>,
    ) -> crate::Result<()> {
        select! {
            // Receive a message from the server.
            message = netbios_client.recieve_bytes() => {
                self.loop_handle_incoming(message).await?;
            }
            // Send a message to the server.
            message = send_channel.recv() => {
                self.loop_handle_outgoing(message, netbios_client).await?;
            },
            // Cancel the loop.
            _ = self.token.cancelled() => {
                return Err(Error::NotConnected);
            }
        }
        Ok(())
    }

    #[cfg(feature = "sync")]
    fn loop_receive(&self, mut netbios_client: NetBiosClient) {
        debug_assert!(netbios_client.read_timeout().unwrap().is_some());
        while !self.is_cancelled() {
            let next = netbios_client.recieve_bytes();
            // Handle polling fail
            if let Err(Error::IoError(ref e)) = next {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
            }
            match self.loop_handle_incoming(next) {
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
                    log::error!("Error in worker recv loop: {}", e);
                }
            }
        }
    }

    #[cfg(feature = "sync")]
    fn loop_send(
        &self,
        mut netbios_client: NetBiosClient,
        send_channel: mpsc::Receiver<Option<NetBiosTcpMessage>>,
    ) {
        loop {
            match self.loop_send_next(send_channel.recv(), &mut netbios_client) {
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
                    log::error!("Error in worker send loop: {}", e);
                }
            }
        }
    }

    #[cfg(feature = "sync")]
    #[inline]
    fn loop_send_next(
        &self,
        message: Result<Option<NetBiosTcpMessage>, mpsc::RecvError>,
        netbios_client: &mut NetBiosClient,
    ) -> crate::Result<()> {
        self.loop_handle_outgoing(message?, netbios_client)
    }

    #[maybe_async]
    async fn loop_handle_incoming(
        self: &Self,
        message: crate::Result<NetBiosTcpMessage>,
    ) -> crate::Result<()> {
        log::trace!("Received message from server.");
        let message = { message? };
        let msg = self.transformer.transform_incoming(message).await?;

        // 2. Handle the message.
        let msg_id = msg.message.header.message_id;

        // Update the state: If awaited, wake up the task. Else, store it.
        let mut state = self.state.lock().await?;
        if let Some(tx) = state.awaiting.remove(&msg_id) {
            log::trace!("Waking up awaiting task for message ID {}.", msg_id);
            tx.send(Ok(msg)).map_err(|_| {
                Error::MessageProcessingError(
                    "Failed to send message to awaiting task.".to_string(),
                )
            })?;
        } else {
            log::trace!("Storing message until awaited: {}.", msg_id);
            state.pending.insert(msg_id, msg);
        }
        Ok(())
    }

    #[maybe_async]
    async fn loop_handle_outgoing(
        self: &Self,
        message: Option<NetBiosTcpMessage>,
        netbios_client: &mut NetBiosClient,
    ) -> crate::Result<()> {
        log::trace!("Sending a message to the server.");

        let message = match message {
            Some(m) => m,
            None => {
                if self.is_cancelled() {
                    return Err(Error::NotConnected);
                } else {
                    return Err(Error::MessageProcessingError(
                        "Empty message cannot be sent to the server.".to_string(),
                    ));
                }
            }
        };
        netbios_client.send_raw(message).await?;

        Ok(())
    }
}
