use std::{cell::RefCell, rc::Rc};

use crate::{
    packets::{
        netbios::NetBiosTcpMessage,
        smb2::{
            header::{SMB2Command, SMB2Status},
            message::{SMB2Message, SMBMessageContent},
        },
    },
    smb_client::PreauthHashValue,
    smb_session::SMBSigner,
};

#[derive(Debug)]
pub struct OutgoingSMBMessage {
    pub message: SMB2Message,

    // signing and encryption information
    pub signer: Option<SMBSigner>,
    /// Whether to finalize the preauth hash after sending this message.
    /// If this is set to true twice per connection, an error will be thrown.
    pub finalize_preauth_hash: bool,
}

impl OutgoingSMBMessage {
    pub fn new(message: SMB2Message) -> OutgoingSMBMessage {
        OutgoingSMBMessage {
            message,
            signer: None,
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
pub struct IncomingSMBMessage {
    pub message: SMB2Message,
    pub raw: NetBiosTcpMessage,
}

/// Options for receiving a message.
///
/// Use a builder pattern to set the options:
/// ```
/// let options = ReceiveOptions::new()
///    .status(SMB2Status::Success)
///    .cmd(Some(SMB2Command::Negotiate));
/// ```
#[derive(Debug)]
pub struct ReceiveOptions {
    /// The expected status of the received message.
    /// If the received message has a different status, an error will be returned.
    pub status: SMB2Status,

    /// If set, this command will be checked against the received command.
    pub cmd: Option<SMB2Command>,
}

impl ReceiveOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(mut self, status: SMB2Status) -> Self {
        self.status = status;
        self
    }

    pub fn cmd(mut self, cmd: Option<SMB2Command>) -> Self {
        self.cmd = cmd;
        self
    }
}

impl Default for ReceiveOptions {
    fn default() -> Self {
        ReceiveOptions {
            status: SMB2Status::Success,
            cmd: None,
        }
    }
}

/// Chain-of-responsibility pattern trait for handling SMB messages
/// outgoing from the client or incoming from the server.
pub trait SMBMessageHandler {
    /// Send a message to the server, returning the result.
    /// This must be implemented. Each handler in the chain must call the next handler,
    /// after possibly modifying the message.
    fn hsendo(
        &mut self,
        msg: OutgoingSMBMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>>;

    /// Receive a message from the server, returning the result.
    /// This must be implemented, and must call the next handler in the chain,
    /// if there is one, using the provided `ReceiveOptions`.
    fn hrecvo(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>>;
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
pub struct SMBHandlerReference<T: SMBMessageHandler + ?Sized> {
    pub handler: Rc<RefCell<T>>,
}

impl<T: SMBMessageHandler> SMBHandlerReference<T> {
    pub fn new(handler: T) -> SMBHandlerReference<T> {
        SMBHandlerReference {
            handler: Rc::new(RefCell::new(handler)),
        }
    }

    pub fn sendo(
        &mut self,
        msg: OutgoingSMBMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().hsendo(msg)
    }

    pub fn send(
        &mut self,
        msg: SMBMessageContent,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.sendo(OutgoingSMBMessage::new(SMB2Message::new(msg)))
    }

    pub fn recvo(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().hrecvo(options)
    }

    pub fn recv(
        &mut self,
        cmd: SMB2Command,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.recvo(ReceiveOptions::new().cmd(Some(cmd)))
    }

    pub fn sendo_recvo(
        &mut self,
        msg: OutgoingSMBMessage,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.sendo(msg)?;
        self.recvo(options)
    }

    pub fn send_recvo(
        &mut self,
        msg: SMBMessageContent,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.send(msg)?;
        self.recvo(options)
    }

    pub fn send_recv(
        &mut self,
        msg: SMBMessageContent,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        let cmd = msg.associated_cmd();
        self.send(msg)?;
        self.recvo(ReceiveOptions::new().cmd(Some(cmd)))
    }
}

// Implement deref that returns the content of Rc<..> above (RefCell<T>)
impl<T: SMBMessageHandler> std::ops::Deref for SMBHandlerReference<T> {
    type Target = RefCell<T>;

    fn deref(&self) -> &Self::Target {
        &self.handler
    }
}

// Clone:
impl<T: SMBMessageHandler> Clone for SMBHandlerReference<T> {
    fn clone(&self) -> Self {
        SMBHandlerReference {
            handler: self.handler.clone(),
        }
    }
}
