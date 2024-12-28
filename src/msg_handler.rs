use std::{cell::RefCell, rc::Rc};

use crate::{packets::{netbios::NetBiosTcpMessage, smb2::message::SMB2Message}, smb_client::PreauthHashState, smb_session::SMBSigner};

#[derive(Debug)]
pub struct OutgoingSMBMessage {
    pub message: SMB2Message,

    // signing and encryption information
    pub signer: Option<SMBSigner>,
    /// Whether to finalize the preauth hash after sending this message.
    /// If this is set to true twice per connection, an error will be thrown.
    pub finalize_preauth_hash: bool
}

impl OutgoingSMBMessage {
    pub fn new(message: SMB2Message) -> OutgoingSMBMessage {
        OutgoingSMBMessage {
            message,
            signer: None,
            finalize_preauth_hash: false
        }
    }
}


#[derive(Debug)]
pub struct SendMessageResult {
    // If finalized, this is set.
    pub preauth_hash: Option<PreauthHashState>
}

impl SendMessageResult {
    pub fn new(preauth_hash: Option<PreauthHashState>) -> SendMessageResult {
        SendMessageResult {
            preauth_hash
        }
    }
}

pub struct IncomingSMBMessage {
    pub message: SMB2Message,
    pub raw: NetBiosTcpMessage
}

/// Chain-of-responsibility pattern trait for handling SMB messages
/// outgoing from the client or incoming from the server.
pub trait SMBMessageHandler {
    fn send(&mut self, msg: OutgoingSMBMessage) -> Result<SendMessageResult, Box<dyn std::error::Error>>;
    fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>>;
}

/// Use this templated struct to hold a handler and access it easily.
pub struct SMBHandlerReference<T: SMBMessageHandler + ?Sized> {
    pub handler: Rc<RefCell<T>>
}

impl<T: SMBMessageHandler> SMBHandlerReference<T> {
    pub fn new(handler: T) -> SMBHandlerReference<T> {
        SMBHandlerReference {
            handler: Rc::new(RefCell::new(handler))
        }
    }

    pub fn send(&mut self, msg: OutgoingSMBMessage) -> Result<SendMessageResult, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().send(msg)
    }

    pub fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.handler.borrow_mut().receive()
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
            handler: self.handler.clone()
        }
    }
}