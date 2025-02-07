use maybe_async::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::{
    sync::{
        oneshot::{channel, Sender},
        Mutex,
    },
    task::JoinHandle,
};

use crate::{msg_handler::IncomingMessage, packets::netbios};

use super::netbios_client::NetBiosClient;

/// SMB2 connection worker.
///
/// This struct is responsible for handling the connection to the server,
/// sending netbios messages from SMB2 messages, and redirecting correct messages when received,
/// if using async, to the correct pending task.
struct ConnectionWorker {
    pending: Arc<Mutex<HashMap<u64, Sender<IncomingMessage>>>>,
    loop_handle: Mutex<Option<JoinHandle<()>>>,
    netbios_client: Mutex<NetBiosClient>,
}

impl ConnectionWorker {
    /// Instantiates a new connection worker.
    #[maybe_async]
    pub async fn start(
        netbios_client: NetBiosClient,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        // Build the worker
        let mut worker = Arc::new(ConnectionWorker {
            pending: Arc::new(Mutex::new(HashMap::new())),
            loop_handle: Mutex::new(None),
            netbios_client,
        });

        // Start the worker loop.
        let mut worker_clone = worker.clone();
        let handle = tokio::spawn(async move { worker_clone.loop_fn().await });
        worker.loop_handle.lock().await.replace(handle);

        Ok(worker)
    }

    /// Receive a message from the server.
    /// This is a user function that will wait for the message to be received.
    #[maybe_async]
    pub async fn send_receive_message(
        self: &mut Arc<Self>,
        msg_id: u64,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        // 1. Insert channel to wait for the message.
        let (tx, rx) = channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.contains_key(&msg_id) {
                return Err("Message ID already exists!".into());
            }
            pending.insert(msg_id, tx);
        }

        // Wait for the message to be received.
        Ok(rx.await?)
    }

    /// Internal message loop handler.
    async fn loop_fn(self: &mut Arc<Self>) {
        loop {
            if let Err(e) = self.loop_fn_receive().await {
                log::error!("Error in connection worker loop: {}", e);
            }
        }
    }

    #[maybe_async]
    async fn loop_fn_receive(self: &mut Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let message = {
            let mut netbios_client = self.netbios_client.lock().await;
            netbios_client.recieve_bytes().await
        };
        Ok(())
    }
}
