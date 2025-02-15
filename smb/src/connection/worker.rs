use crate::sync_helpers::*;
use maybe_async::*;
use std::sync::atomic::AtomicBool;
#[cfg(feature = "sync")]
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
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
/// One-per connection, hence takes ownership of [NetBiosClient] on [WorkerBase::start].
#[derive(Debug)]
pub struct WorkerBase<T>
where
    T: WorkerBackend + std::fmt::Debug,
    T::AwaitingNotifier: std::fmt::Debug,
{
    state: Mutex<WorkerAwaitState<T>>,
    backend: Mutex<Option<Arc<T>>>,

    transformer: Transformer,

    /// A channel to send messages to the worker.
    sender: mpsc::Sender<T::SendMessage>,
    stopped: AtomicBool,
}

#[cfg(feature = "async")]
pub type WorkerImpl = WorkerBase<AsyncBackend>;
#[cfg(feature = "sync")]
pub type WorkerImpl = WorkerBase<SyncBackend>;

/// Holds state for the worker, regarding messages to be received.
#[derive(Debug)]
struct WorkerAwaitState<T>
where
    T: WorkerBackend,
    T::AwaitingNotifier: std::fmt::Debug,
{
    /// Stores the awaiting tasks that are waiting for a specific message ID.
    awaiting: HashMap<u64, T::AwaitingNotifier>,
    /// Stores the pending messages, waiting to be receive()-d.
    pending: HashMap<u64, IncomingMessage>,
}

impl<T> WorkerAwaitState<T>
where
    T: WorkerBackend,
    T::AwaitingNotifier: std::fmt::Debug,
{
    fn new() -> Self {
        Self {
            awaiting: HashMap::new(),
            pending: HashMap::new(),
        }
    }
}

impl<T> WorkerBase<T>
where
    T: WorkerBackend + std::fmt::Debug,
    T::AwaitingNotifier: std::fmt::Debug,
{
    /// Instantiates a new connection worker.
    #[maybe_async]
    pub async fn start(netbios_client: NetBiosClient) -> crate::Result<Arc<Self>> {
        // Build the worker
        let (tx, rx) = T::make_send_channel_pair();
        let worker = Arc::new(WorkerBase::<T> {
            state: Mutex::new(WorkerAwaitState::new()),
            backend: Default::default(),
            transformer: Transformer::default(),
            sender: tx,
            stopped: AtomicBool::new(false),
        });

        worker
            .backend
            .lock()
            .await?
            .replace(T::start(netbios_client, worker.clone(), rx).await?);

        Ok(worker)
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
    pub async fn stop(&self) -> crate::Result<()> {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        {
            self.backend
                .lock()
                .await?
                .take()
                .ok_or(Error::InvalidState(
                    "No backend present for worker.".to_string(),
                ))?
        }
        .stop()
        .await
    }

    #[maybe_async]
    pub fn stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
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

        let message = T::wrap_msg_to_send(message);

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

            if self.stopped() {
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

            let (tx, rx) = T::make_notifier_awaiter_pair();
            state.awaiting.insert(msg_id, tx);
            rx
        };

        let wait_result = T::wait_on_waiter(wait_for_receive).await;

        // Wait for the message to be received.
        Ok(wait_result.map_err(|_| {
            Error::MessageProcessingError("Failed to receive message from worker!".to_string())
        })?)
    }

    #[maybe_async]
    pub async fn loop_handle_incoming(
        self: &Arc<Self>,
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
            T::send_notify(tx, Ok(msg))?;
        } else {
            log::trace!("Storing message until awaited: {}.", msg_id);
            state.pending.insert(msg_id, msg);
        }
        Ok(())
    }

    #[maybe_async]
    pub async fn loop_handle_outgoing(
        self: &Arc<Self>,
        message: Option<NetBiosTcpMessage>,
        netbios_client: &mut NetBiosClient,
    ) -> crate::Result<()> {
        log::trace!("Sending a message to the server.");

        let message = match message {
            Some(m) => m,
            None => {
                if self.stopped() {
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

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)] // for maybe_async.
pub trait WorkerBackend {
    type SendMessage;
    type AwaitingNotifier;
    type AwaitingWaiter;

    async fn start(
        netbios_client: NetBiosClient,
        worker: Arc<WorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>>
    where
        Self: std::fmt::Debug + Sized,
        Self::AwaitingNotifier: std::fmt::Debug;
    async fn stop(&self) -> crate::Result<()>;
    fn is_cancelled(&self) -> bool;

    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage;
    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter);
    // TODO: Consider typing the tx/rx in the trait, like the notifier/awaiter.
    fn make_send_channel_pair() -> ( 
        mpsc::Sender<Self::SendMessage>,
        mpsc::Receiver<Self::SendMessage>,
    );

    async fn wait_on_waiter(waiter: Self::AwaitingWaiter) -> crate::Result<IncomingMessage>;
    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> crate::Result<()>;
}

#[cfg(feature = "sync")]
#[derive(Debug)]
pub struct SyncBackend {
    worker: Arc<WorkerBase<Self>>,

    /// The loops' handles for the worker.
    loop_handles: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,
    stopped: AtomicBool,
}

#[cfg(feature = "sync")]
impl SyncBackend {
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
            match self.worker.loop_handle_incoming(next) {
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

    #[inline]
    fn loop_send_next(
        &self,
        message: Result<Option<NetBiosTcpMessage>, mpsc::RecvError>,
        netbios_client: &mut NetBiosClient,
    ) -> crate::Result<()> {
        self.worker.loop_handle_outgoing(message?, netbios_client)
    }
}

#[cfg(feature = "sync")]
impl WorkerBackend for SyncBackend {
    type SendMessage = Option<NetBiosTcpMessage>;

    type AwaitingNotifier = std::sync::mpsc::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = std::sync::mpsc::Receiver<crate::Result<IncomingMessage>>;

    fn start(
        netbios_client: NetBiosClient,
        worker: Arc<WorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>>
    where
        Self: std::fmt::Debug,
        Self::AwaitingNotifier: std::fmt::Debug,
    {
        let backend = Arc::new(Self {
            worker,
            loop_handles: Mutex::new(None),
            stopped: AtomicBool::new(false),
        });

        // Start the worker loops - send and receive.
        let netbios_receive = netbios_client;
        let backend_receive = backend.clone();
        let netbios_send = netbios_receive.try_clone()?;
        let backend_send = backend.clone();

        netbios_receive.set_read_timeout(Some(Duration::from_millis(100)))?;

        let handle1 = std::thread::spawn(move || backend_receive.loop_receive(netbios_receive));
        let handle2 =
            std::thread::spawn(move || backend_send.loop_send(netbios_send, send_channel_recv));

        backend
            .loop_handles
            .lock()
            .unwrap()
            .replace((handle1, handle2));

        Ok(backend)
    }

    fn stop(&self) -> crate::Result<()> {
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
        self.worker.sender.send(None).unwrap();

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

    fn is_cancelled(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage {
        Some(msg)
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        std::sync::mpsc::channel()
    }

    fn wait_on_waiter(waiter: Self::AwaitingWaiter) -> crate::Result<IncomingMessage> {
        waiter
            .recv()
            .map_err(|_| Error::MessageProcessingError("Failed to receive message.".to_string()))?
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
        mpsc::channel()
    }
}

#[cfg(feature = "async")]
#[derive(Debug)]
pub struct AsyncBackend {
    /// The loop handle for the worker.
    loop_handle: Mutex<Option<JoinHandle<()>>>,

    token: CancellationToken,
}

#[cfg(feature = "async")]
impl AsyncBackend {
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Internal message loop handler.
    async fn loop_fn(
        self: Arc<Self>,
        mut netbios_client: NetBiosClient,
        mut rx: mpsc::Receiver<NetBiosTcpMessage>,
        worker: Arc<WorkerBase<Self>>,
    ) {
        log::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref
                .handle_next_msg(&mut netbios_client, &mut rx, &worker)
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
        // TODO: Handle cleanup recursively.
        log::debug!("Cleaning up worker loop.");
        rx.close();
        if let Ok(mut state) = worker.state.lock().await {
            for (_, tx) in state.awaiting.drain() {
                tx.send(Err(Error::NotConnected)).unwrap();
            }
        }
    }

    /// Handles the next message in the loop:
    /// - receives a message, transforms it, and sends it to the correct awaiting task.
    /// - sends a message to the server.
    async fn handle_next_msg(
        self: &Self,
        netbios_client: &mut NetBiosClient,
        send_channel: &mut mpsc::Receiver<NetBiosTcpMessage>,
        worker: &Arc<WorkerBase<Self>>,
    ) -> crate::Result<()> {
        select! {
            // Receive a message from the server.
            message = netbios_client.recieve_bytes() => {
                worker.loop_handle_incoming(message).await?;
            }
            // Send a message to the server.
            message = send_channel.recv() => {
                worker.loop_handle_outgoing(message, netbios_client).await?;
            },
            // Cancel the loop.
            _ = self.token.cancelled() => {
                return Err(Error::NotConnected);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
impl WorkerBackend for AsyncBackend {
    type SendMessage = NetBiosTcpMessage;

    type AwaitingNotifier = oneshot::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = oneshot::Receiver<crate::Result<IncomingMessage>>;

    async fn start(
        netbios_client: NetBiosClient,
        worker: Arc<WorkerBase<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>> {
        // Start the worker loop.
        let backend = Arc::new(Self {
            loop_handle: Mutex::new(None),
            token: CancellationToken::new(),
        });
        let backend_clone = backend.clone();
        let handle = tokio::spawn(async move {
            backend_clone
                .loop_fn(netbios_client, send_channel_recv, worker)
                .await
        });
        backend.loop_handle.lock().await?.replace(handle);

        Ok(backend)
    }

    async fn stop(&self) -> crate::Result<()> {
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

    fn is_cancelled(&self) -> bool {
        todo!()
    }

    fn wrap_msg_to_send(msg: NetBiosTcpMessage) -> Self::SendMessage {
        msg
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        oneshot::channel()
    }

    async fn wait_on_waiter(waiter: Self::AwaitingWaiter) -> crate::Result<IncomingMessage> {
        waiter
            .await
            .map_err(|_| Error::MessageProcessingError("Failed to receive message.".to_string()))?
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
