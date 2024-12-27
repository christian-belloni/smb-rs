use crate::{packets::{netbios::NetBiosTcpMessage, smb2::message::SMB2Message}, smb_session::SMBSigner};

#[derive(Debug)]
pub struct OutgoingSMBMessage {
    pub message: SMB2Message,

    // signing and encryption information
    pub signer: Option<SMBSigner>
}

impl OutgoingSMBMessage {
    pub fn new(message: SMB2Message) -> OutgoingSMBMessage {
        OutgoingSMBMessage {
            message,
            signer: None
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
    fn send(&mut self, msg: OutgoingSMBMessage) -> Result<(), Box<dyn std::error::Error>>;
    fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>>;
}