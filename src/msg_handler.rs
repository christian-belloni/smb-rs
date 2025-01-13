use std::{cell::RefCell, rc::Rc};

use crate::{
    client::PreauthHashValue, packets::{
        netbios::NetBiosTcpMessage,
        smb2::{
            header::{Command, Status},
            message::{Content, Message},
        },
    }, session::{MessageEncryptor, MessageSigner}
};

#[derive(Debug)]
pub struct OutgoingMessage {
    pub message: Message,

    // signing and encryption information
    pub signer: Option<MessageSigner>,
    pub encryptor: Option<MessageEncryptor>,

    /// Whether to finalize the preauth hash after sending this message.
    /// If this is set to true twice per connection, an error will be thrown.
    pub finalize_preauth_hash: bool,
}

impl OutgoingMessage {
    pub fn new(message: Message) -> OutgoingMessage {
        OutgoingMessage {
            message,
            signer: None,
            encryptor: None,
            finalize_preauth_hash: false,
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
    pub message: Message,
    pub raw: NetBiosTcpMessage,
}

/// Options for receiving a message.
///
/// Use a builder pattern to set the options:
/// ```
/// use smb::packets::smb2::header::{Command, Status};
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
        }
    }
}

/// Chain-of-responsibility pattern trait for handling SMB messages
/// outgoing from the client or incoming from the server.
pub trait MessageHandler {
    /// Send a message to the server, returning the result.
    /// This must be implemented. Each handler in the chain must call the next handler,
    /// after possibly modifying the message.
    fn hsendo(
        &mut self,
        msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>>;

    /// Receive a message from the server, returning the result.
    /// This must be implemented, and must call the next handler in the chain,
    /// if there is one, using the provided `ReceiveOptions`.
    fn hrecvo(
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

    pub fn sendo(
        &mut self,
        msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().hsendo(msg)
    }

    pub fn send(&mut self, msg: Content) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.sendo(OutgoingMessage::new(Message::new(msg)))
    }

    pub fn recvo(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().hrecvo(options)
    }

    pub fn recv(&mut self, cmd: Command) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.recvo(ReceiveOptions::new().cmd(Some(cmd)))
    }

    pub fn sendo_recvo(
        &mut self,
        msg: OutgoingMessage,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.sendo(msg)?;
        self.recvo(options)
    }

    pub fn send_recvo(
        &mut self,
        msg: Content,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        self.send(msg)?;
        self.recvo(options)
    }

    pub fn send_recv(
        &mut self,
        msg: Content,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let cmd = msg.associated_cmd();
        self.send(msg)?;
        self.recvo(ReceiveOptions::new().cmd(Some(cmd)))
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
