use maybe_async::*;
use tokio::select;

#[cfg(not(feature = "async"))]
use std::cell::OnceCell;
use std::{collections::HashMap, sync::Arc};
#[cfg(feature = "async")]
use tokio::{
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
};

use crate::{
    msg_handler::{IncomingMessage, OutgoingMessage, SendMessageResult},
    packets::netbios::NetBiosTcpMessage,
    Error,
};

use super::{
    negotiation_state::NegotiateState, netbios_client::NetBiosClient,
    transformer::Transformer,
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

    /// The loop handle for the worker.
    loop_handle: Mutex<Option<JoinHandle<()>>>,

    transformer: Transformer,
    /// A channel to send messages to the worker.
    sender: mpsc::Sender<NetBiosTcpMessage>,
}

/// Holds state for the worker, regarding messages to be received.
#[derive(Debug, Default)]
struct WorkerAwaitState {
    /// Stores the awaiting tasks that are waiting for a specific message ID.
    awaiting: HashMap<u64, oneshot::Sender<IncomingMessage>>,
    /// Stores the pending messages, waiting to be receive()-d.
    pending: HashMap<u64, IncomingMessage>,
}

impl ConnectionWorker {
    /// Instantiates a new connection worker.
    #[maybe_async]
    pub async fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>> {
        // Build the worker
        let (tx, rx) = mpsc::channel(32);
        let worker = Arc::new(ConnectionWorker {
            state: Mutex::new(WorkerAwaitState::default()),
            loop_handle: Mutex::new(None),
            transformer: Transformer::default(),
            sender: tx,
        });

        // Start the worker loop.
        let worker_clone = worker.clone();
        let handle = tokio::spawn(async move { worker_clone.loop_fn(netbios_client, rx).await });
        worker.loop_handle.lock().await.replace(handle);

        Ok(worker)
    }

    #[maybe_async]
    pub async fn negotaite_complete(&self, neg_state: &NegotiateState) {
        self.transformer.negotiated(neg_state).await.unwrap();
    }

    #[maybe_async]
    pub async fn send(self: &Self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let finalize_preauth_hash = msg.finalize_preauth_hash;
        let message = { self.transformer.tranform_outgoing(msg).await? };

        let hash = match finalize_preauth_hash {
            true => Some(self.transformer.finalize_preauth_hash().await),
            false => None,
        };

        self.sender.send(message).await.map_err(|_| {
            Error::MessageProcessingError("Failed to send message to worker!".to_string())
        })?;

        Ok(SendMessageResult::new(hash.clone()))
    }

    /// Receive a message from the server.
    /// This is a user function that will wait for the message to be received.
    #[maybe_async]
    pub async fn receive(self: &Self, msg_id: u64) -> crate::Result<IncomingMessage> {
        // 1. Insert channel to wait for the message, or return the message if already received.
        let wait_for_receive = {
            let mut state = self.state.lock().await;
            if state.pending.contains_key(&msg_id) {
                return Ok(state.pending.remove(&msg_id).unwrap());
            }
            let (tx, rx) = oneshot::channel();
            state.awaiting.insert(msg_id, tx);
            rx
        };

        // Wait for the message to be received.
        Ok(wait_for_receive.await.map_err(|_| {
            Error::MessageProcessingError("Failed to receive message from worker!".to_string())
        })?)
    }

    /// Internal message loop handler.
    async fn loop_fn(
        self: Arc<Self>,
        mut netbios_client: NetBiosClient,
        mut rx: mpsc::Receiver<NetBiosTcpMessage>,
    ) {
        let self_ref = self.as_ref();
        loop {
            if let Err(e) = self_ref.handle_next_msg(&mut netbios_client, &mut rx).await {
                log::error!("Error in connection worker loop: {}", e);
            }
        }
    }

    /// Handles the next message in the loop:
    /// - receives a message, transforms it, and sends it to the correct awaiting task.
    /// - sends a message to the server.
    #[maybe_async]
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
                let message = {
                    message.ok_or("Failed to receive message from channel.")
                    .map_err(|e| Error::MessageProcessingError(e.to_string()))?
                };
                netbios_client.send_raw(message).await?;
            }
        }
        Ok(())
    }

    #[maybe_async]
    async fn loop_handle_incoming(
        self: &Self,
        message: crate::Result<NetBiosTcpMessage>,
    ) -> crate::Result<()> {
        let message = { message? };
        let msg = self.transformer.transform_incoming(message).await?;

        // 2. Handle the message.
        let msg_id = msg.message.header.message_id;

        // Update the state: If awaited, wake up the task. Else, store it.
        let mut state = self.state.lock().await;
        if let Some(tx) = state.awaiting.remove(&msg_id) {
            tx.send(msg).map_err(|_| {
                Error::MessageProcessingError(
                    "Failed to send message to awaiting task.".to_string(),
                )
            })?;
        } else {
            state.pending.insert(msg_id, msg);
        }
        Ok(())
    }
}
