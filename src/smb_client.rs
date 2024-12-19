use std::{cell::OnceCell, error::Error, fmt::Display};
use binrw::prelude::*;
use rand::Rng;
use sspi::{AuthIdentity, OwnedSecurityBuffer, Secret, SecurityBufferType, Username};

use crate::{authenticator::GssAuthenticator, netbios_client::NetBiosClient, packets::{netbios::NetBiosMessageContent, smb1::SMB1NegotiateMessage, smb2::{header::{SMB2Command, SMB2HeaderFlags}, message::{SMB2Message, SMBMessageContent}, negotiate::{SMBNegotiateRequest, SMBNegotiateResponse, SMBNegotiateResponseDialect}, setup::SMB2SessionSetupRequest}}};

struct SmbNegotiateState {
    server_guid: u128,

    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,

    gss_negotiate_token: Vec<u8>,
}

pub struct SMBClient {
    client_guid: u128,
    netbios_client: NetBiosClient,

    // Negotiation-related state.
    negotiate_state: OnceCell<SmbNegotiateState>,
    // Auth
    authenticator: Option<GssAuthenticator>,
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
            client_guid: rand::rngs::OsRng.gen(),
            netbios_client: NetBiosClient::new(),
            negotiate_state: OnceCell::new(),
            authenticator: None,
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        self.netbios_client.connect(address)
    }

    fn receive_smb2(&mut self, command: SMB2Command, require_success: bool) -> Result<SMB2Message, Box<dyn Error>> {
        let netbios_message = self.netbios_client.receive()?;
        let smb2_message = match netbios_message {
            NetBiosMessageContent::SMB2Message(smb2_message) => Some(smb2_message),
            _ => None
        }.ok_or("Expected SMB2 message")?;
        if smb2_message.header.command != command {
            return Err("Unexpected SMB2 command".into());
        };
        if !smb2_message.header.flags.server_to_redir() {
            return Err("Unexpected SMB2 message direction (Not a response)".into());
        }
        if require_success && smb2_message.header.status != 0 {
            return Err("SMB2 message status is not success".into());
        }
        Ok(smb2_message)
    }

    fn send_and_receive_smb2(&mut self, message: SMB2Message, require_success: bool) -> Result<SMB2Message, Box<dyn Error>> {
        let expected_command = message.header.command;
        self.netbios_client.send(NetBiosMessageContent::SMB2Message(message))?;
        self.receive_smb2(expected_command, require_success)
    }

    fn negotiate_smb1(&mut self) -> Result<(), Box<dyn Error>> {
        // 1. Send SMB1 negotiate request
        self.netbios_client.send(NetBiosMessageContent::SMB1Message(SMB1NegotiateMessage::new()))?;

        // 2. Expect SMB2 negotiate response
        let smb2_response = self.receive_smb2(SMB2Command::Negotiate, true)?;
        let smb2_negotiate_response = match smb2_response.content {
            SMBMessageContent::SMBNegotiateResponse(response) => Some(response),
            _ => None
        }.unwrap();

        // 3. Make sure dialect is smb2*
        if smb2_negotiate_response.dialect_revision != SMBNegotiateResponseDialect::Smb02Wildcard {
            return Err("Unexpected SMB2 dialect revision".into());
        }
        Ok(())
    }

    fn negotiate_smb2(&mut self) -> Result<(), Box<dyn Error>> {
        // Send SMB2 negotiate request
        let smb2_response = self.send_and_receive_smb2(SMB2Message::new(
            SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest::new(self.client_guid)),
            1, 0, 0, SMB2HeaderFlags::new(), 0
        ), true)?;
        let smb2_negotiate_response = match smb2_response.content {
            SMBMessageContent::SMBNegotiateResponse(response) => Some(response),
            _ => None
        }.unwrap();

        let negotiate_state = SmbNegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_negotiate_token: smb2_negotiate_response.buffer,
        };

        self.negotiate_state.set(negotiate_state).map_err(|_| "Negotiate state already set")?;

        Ok(())
    }

    pub fn negotiate(&mut self) -> Result<(), Box<dyn Error>> {
        self.negotiate_smb1()?;
        self.negotiate_smb2()
    }

    pub fn authenticate(&mut self, user_name: String, password: String) -> Result<(), Box<dyn Error>> {
        let negotate_state = self.negotiate_state.get().ok_or(SmbClientNotConnectedError)?;
        let identity = AuthIdentity {
            username: Username::new(&user_name, Some("WORKGROUP"))?,
            password: Secret::new(password),
        };
        let (mut authenticator, mut next_buf) = GssAuthenticator::build(&negotate_state.gss_negotiate_token, identity)?;
        let mut response = self.send_and_receive_smb2(SMB2Message::new(
            SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(next_buf)),
            2, 1, 33, SMB2HeaderFlags::new().with_priority_mask(1), 0
        ), false)?;

        if response.header.status != 0xc0000016 {
            return Err("Expected STATUS_MORE_PROCESSING_REQUIRED".into());
        }
        let session_id = response.header.session_id;
        
        while !authenticator.is_authenticated()? {
            let setup_response = match response.content {
                SMBMessageContent::SMBSessionSetupResponse(response) => Some(response),
                _ => None
            }.unwrap();
    
            next_buf = authenticator.next(setup_response.buffer)?;
            response = self.send_and_receive_smb2(SMB2Message::new(
                SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(next_buf)),
                3, 1, 65, SMB2HeaderFlags::new().with_priority_mask(1), session_id
            ), false)?;    
        }
        Ok(())
    }

}