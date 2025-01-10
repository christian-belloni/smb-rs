use std::{cell::RefCell, rc::Rc};

use crate::{
    packets::{
        netbios::NetBiosTcpMessage,
        smb2::{header::{SMB2Command, SMB2Status}, message::SMB2Message},
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
    fn send(
        &mut self,
        msg: OutgoingSMBMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>>;

    /// Receive a message from the server, returning the result.
    /// This must be implemented, and must call the next handler in the chain,
    /// if there is one, using the provided `ReceiveOptions`.
    fn receive_options(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>>;
}

/// Use this templated struct to hold a handler and access it easily.
pub struct SMBHandlerReference<T: SMBMessageHandler + ?Sized> {
    pub handler: Rc<RefCell<T>>,
}

impl<T: SMBMessageHandler> SMBHandlerReference<T> {
    pub fn new(handler: T) -> SMBHandlerReference<T> {
        SMBHandlerReference {
            handler: Rc::new(RefCell::new(handler)),
        }
    }

    /// [SMBMessageHandler::send]
    pub fn send(
        &mut self,
        msg: OutgoingSMBMessage,
    ) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().send(msg)
    }

    /// [SMBMessageHandler::receive_options]
    pub fn receive_options(
        &mut self,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().receive_options(options)
    }

    /// Receive a message from the server, returning the result,
    /// using the default options.
    /// - Expecting a status of [SMB2Status::Success].
    pub fn receive(&mut self, cmd: SMB2Command) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.receive_options(ReceiveOptions::new().cmd(Some(cmd)))
    }

    /// Send and receive a message, returning the result.
    /// See [SMBHandlerReference::send] and [SMBHandlerReference::receive_options] for details.
    /// Use [SMBHandlerReference::send_receive] for a more concise version.
    pub fn send_receive_options(
        &mut self,
        msg: OutgoingSMBMessage,
        options: ReceiveOptions,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.send(msg)?;
        self.receive_options(options)
    }

    /// Send and receive a message, returning the result.
    /// Expects a successful status and the same command as the sent message.
    /// To customize the receive options, use [SMBHandlerReference::send_receive_options].
    pub fn send_receive(
        &mut self,
        msg: OutgoingSMBMessage,
    ) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        let cmd = msg.message.header.command;
        self.send(msg)?;
        self.receive_options(
            ReceiveOptions::new()
                .cmd(Some(cmd)),
        )
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
