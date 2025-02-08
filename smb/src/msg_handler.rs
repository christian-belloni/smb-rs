use crate::{connection::preauth_hash::PreauthHashValue, packets::smb2::*};
use maybe_async::*;
use std::{cell::RefCell, rc::Rc};

#[derive(Debug)]
pub struct OutgoingMessage {
    pub message: PlainMessage,

    /// Whether to finalize the preauth hash after sending this message.
    /// If this is set to true twice per connection, an error will be thrown.
    pub finalize_preauth_hash: bool,

    /// Ask the sender to compress the message before sending, if possible.
    pub compress: bool,
    /// Ask the sender to encrypt the message before sending, if possible.
    pub encrypt: bool,
    // Signing is set through message/header/flags/signed.
}

impl OutgoingMessage {
    pub fn new(message: PlainMessage) -> OutgoingMessage {
        OutgoingMessage {
            message,
            finalize_preauth_hash: false,
            compress: true,
            encrypt: false,
        }
    }
}

#[derive(Debug)]
pub struct SendMessageResult {
    // If finalized, this is set.
    pub preauth_hash: Option<PreauthHashValue>,
}

impl SendMessageResult {
    pub fn new(preauth_hash: Option<PreauthHashValue>) -> SendMessageResult {
        SendMessageResult { preauth_hash }
    }
}

#[derive(Debug)]
pub struct IncomingMessage {
    pub message: PlainMessage,
    /// The raw message received from the server, after applying transformations (e.g. decompression).
    pub raw: Vec<u8>,

    // How did the message arrive?
    pub form: MessageForm,
}

#[derive(Debug, Default)]
pub struct MessageForm {
    pub compressed: bool,
    pub encrypted: bool,
}

/// Options for receiving a message.
///
/// Use a builder pattern to set the options:
/// ```
/// use smb::packets::smb2::*;
/// use smb::msg_handler::ReceiveOptions;
///
/// let options = ReceiveOptions::new()
///    .status(Status::Success)
///    .cmd(Some(Command::Negotiate));
/// ```
#[derive(Debug)]
pub struct ReceiveOptions {
    /// The expected status of the received message.
    /// If the received message has a different status, an error will be returned.
    pub status: Status,

    /// If set, this command will be checked against the received command.
    pub cmd: Option<Command>,

    /// When receiving a message, only messages with this msgid will be returned.
    /// This is mostly used for async message handling, where the client is waiting for a specific message.
    pub msgid_filter: u64
}

impl ReceiveOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    pub fn cmd(mut self, cmd: Option<Command>) -> Self {
        self.cmd = cmd;
        self
    }
}

impl Default for ReceiveOptions {
    fn default() -> Self {
        ReceiveOptions {
            status: Status::Success,
            cmd: None,
            msgid_filter: 0,
        }
    }
}

/// Chain-of-responsibility pattern trait for handling SMB messages
/// outgoing from the client or incoming from the server.
#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)] // We need `async`-ed trait functions for the #[maybe_async] macro.
pub trait MessageHandler {
    /// Send a message to the server, returning the result.
    /// This must be implemented. Each handler in the chain must call the next handler,
    /// after possibly modifying the message.
    async fn hsendo(
        &mut self,
        msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>>;

    /// Receive a message from the server, returning the result.
    /// This must be implemented, and must call the next handler in the chain,
    /// if there is one, using the provided `ReceiveOptions`.
    async fn hrecvo(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>>;
}

/// A templated shared reference to an SMB message handler.
///
/// Provides a more ergonomic way to interact with the handler.
/// Provided methods are:
/// - `send*`: Send a message content to the server.
/// - `receive*`: Receive a message from the server.
/// - `send*_receive*`: Send a message and receive a response.
/// - `*o`: Send a message and receive a response with custom options:
///     - `sendo`: Send a message with custom, low-level handler options.
///     - `recvo`: Receive a message with custom, low-level handler options.
pub struct HandlerReference<T: MessageHandler + ?Sized> {
    pub handler: Rc<RefCell<T>>,
}

impl<T: MessageHandler> HandlerReference<T> {
    pub fn new(handler: T) -> HandlerReference<T> {
        HandlerReference {
            handler: Rc::new(RefCell::new(handler)),
        }
    }

    #[maybe_async]
    pub async fn sendo(
        &mut self,
        msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().hsendo(msg).await
    }

    #[maybe_async]
    pub async fn send(
        &mut self,
        msg: Content,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.sendo(OutgoingMessage::new(PlainMessage::new(msg)))
            .await
    }

    #[maybe_async]
    pub async fn recvo(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().hrecvo(options).await
    }

    #[maybe_async]
    pub async fn recv(
        &mut self,
        cmd: Command,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.recvo(ReceiveOptions::new().cmd(Some(cmd))).await
    }

    #[maybe_async]
    pub async fn sendo_recvo(
        &mut self,
        msg: OutgoingMessage,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.sendo(msg).await?;
        self.recvo(options).await
    }

    #[maybe_async]
    pub async fn send_recvo(
        &mut self,
        msg: Content,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.send(msg).await?;
        self.recvo(options).await
    }

    #[maybe_async]
    pub async fn send_recv(
        &mut self,
        msg: Content,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let cmd = msg.associated_cmd();
        self.send(msg).await?;
        self.recvo(ReceiveOptions::new().cmd(Some(cmd))).await
    }
}

// Implement deref that returns the content of Rc<..> above (RefCell<T>)
impl<T: MessageHandler> std::ops::Deref for HandlerReference<T> {
    type Target = RefCell<T>;

    fn deref(&self) -> &Self::Target {
        &self.handler
    }
}

// Clone:
impl<T: MessageHandler> Clone for HandlerReference<T> {
    fn clone(&self) -> Self {
        HandlerReference {
            handler: self.handler.clone(),
        }
    }
}
