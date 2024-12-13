use std::{error::Error, fmt::Display};
use binrw::prelude::*;
use rand::Rng;

use crate::{netbios_client::NetBiosClient, packets::{netbios::NetBiosTcpMessageContent, smb1::SMB1NegotiateMessage}};



pub struct SMBClient {
    _client_guid: u128,
    netbios_client: NetBiosClient
}

#[derive(Debug, Clone)]
pub struct SmbClientNotConnectedError;

impl Display for SmbClientNotConnectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMB client is not connected")
    }
}

impl Error for SmbClientNotConnectedError {}

impl SMBClient {
    pub fn new() -> SMBClient {
        SMBClient {
            _client_guid: rand::rngs::OsRng.gen(),
            netbios_client: NetBiosClient::new()
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        self.netbios_client.connect(address)
    }

    pub fn negotiate(&mut self) -> Result<(), Box<dyn Error>> {
        // Send SMB1 packet
        self.netbios_client.send(NetBiosTcpMessageContent::SMB1Message(SMB1NegotiateMessage::new()))?;
        let smb2_response = self.netbios_client.receive()?;
        if let NetBiosTcpMessageContent::SMB1Message(smb1_response) = smb2_response.message {
            dbg!(smb1_response);
            return Err("Expected SMB2 response, got SMB1 response".into());
        }
        dbg!(smb2_response);
        Ok(())
    }
}