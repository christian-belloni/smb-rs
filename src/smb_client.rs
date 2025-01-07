use binrw::prelude::*;
use core::panic;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::{cell::OnceCell, error::Error, fmt::Display};

use crate::{
    msg_handler::{
        IncomingSMBMessage, OutgoingSMBMessage, SMBHandlerReference, SMBMessageHandler,
        SendMessageResult,
    },
    netbios_client::NetBiosClient,
    packets::{
        netbios::{NetBiosMessageContent, NetBiosTcpMessage},
        smb1::SMB1NegotiateMessage,
        smb2::{
            message::{SMB2Message, SMBMessageContent},
            negotiate::{
                HashAlgorithm, SMBDialect, SMBNegotiateContextType, SMBNegotiateContextValue,
                SMBNegotiateRequest, SMBNegotiateResponseDialect, SigningAlgorithmId,
            },
        },
    },
    smb_crypto::SMBCrypto,
    smb_session::SMBSession,
};

pub type PreauthHashValue = [u8; 64];

#[derive(Debug, Clone)]
pub enum PreauthHashState {
    InProgress(PreauthHashValue),
    Finished(PreauthHashValue),
}

impl PreauthHashState {
    pub fn next(self, data: &[u8]) -> PreauthHashState {
        match self {
            PreauthHashState::InProgress(hash) => {
                let mut hasher = Sha512::new();
                hasher.update(&hash);
                hasher.update(data);
                PreauthHashState::InProgress(hasher.finalize().into())
            }
            _ => panic!("Preauth hash not started/already finished."),
        }
    }

    pub fn finish(self) -> PreauthHashState {
        match self {
            PreauthHashState::InProgress(hash) => PreauthHashState::Finished(hash),
            _ => panic!("Preauth hash not started"),
        }
    }

    pub fn unwrap_final_hash(self) -> PreauthHashValue {
        match self {
            PreauthHashState::Finished(hash) => hash,
            _ => panic!("Preauth hash not finished"),
        }
    }
}

impl Default for PreauthHashState {
    fn default() -> PreauthHashState {
        PreauthHashState::InProgress([0; 64])
    }
}

#[derive(Debug)]
pub struct SmbNegotiateState {
    pub server_guid: u128,

    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,

    pub gss_negotiate_token: Vec<u8>,

    pub selected_dialect: SMBDialect,
}

impl SmbNegotiateState {
    pub fn get_gss_token(&self) -> &[u8] {
        &self.gss_negotiate_token
    }
}

pub struct SMBClient {
    handler: SMBHandlerReference<SMBClientMessageHandler>,
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
            handler: SMBHandlerReference::new(SMBClientMessageHandler::new()),
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        self.handler.borrow_mut().netbios_client.connect(address)?;
        log::info!("Connected to {}", address);
        Ok(())
    }

    fn negotiate_smb1(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Negotiating SMB1");
        // 1. Send SMB1 negotiate request
        self.handler
            .borrow_mut()
            .netbios_client
            .send(NetBiosMessageContent::SMB1Message(
                SMB1NegotiateMessage::new(),
            ))?;

        // 2. Expect SMB2 negotiate response
        let smb2_response = self.handler.receive()?;
        let smb2_negotiate_response = match smb2_response.message.content {
            SMBMessageContent::SMBNegotiateResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        // 3. Make sure dialect is smb2*
        if smb2_negotiate_response.dialect_revision != SMBNegotiateResponseDialect::Smb02Wildcard {
            return Err("Unexpected SMB2 dialect revision".into());
        }
        Ok(())
    }

    fn negotiate_smb2(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Negotiating SMB2");
        // Start preauth hash.
        self.handler.borrow_mut().preauth_hash = Some(PreauthHashState::default());

        // Send SMB2 negotiate request
        let neg_req = OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest::new(
                "AVIV-MBP".to_string(),
                self.handler.borrow().client_guid,
                SMBCrypto::SIGNING_ALGOS.into(),
            )),
        ));
        self.handler.send(neg_req)?;

        let smb2_response_raw = self.handler.receive()?;

        let smb2_negotiate_response = match smb2_response_raw.message.content {
            SMBMessageContent::SMBNegotiateResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        // well, only 3.1 is supported for starters.
        if smb2_negotiate_response.dialect_revision != SMBNegotiateResponseDialect::Smb0311 {
            return Err("Unexpected SMB2 dialect revision".into());
        }

        if let None = smb2_negotiate_response.negotiate_context_list {
            return Err("Negotiate context list is missing".into());
        }

        let context_list = &smb2_negotiate_response.negotiate_context_list.unwrap();

        // If signing algorithm is not AES-GMAC, we're not supporting it just yet.
        if !context_list.iter().any(|context| match &context.data {
            SMBNegotiateContextValue::SigningCapabilities(sc) => sc
                .signing_algorithms
                .iter()
                .any(|a| SMBCrypto::SIGNING_ALGOS.contains(a)),
            _ => false,
        }) {
            return Err("AES-CMAC signing algorithm is not supported".into());
        }

        // Make sure preauth integrity capability is SHA-512.
        if !context_list
            .iter()
            .filter(|context| {
                context.context_type == SMBNegotiateContextType::PreauthIntegrityCapabilities
            })
            .all(|context| match &context.data {
                SMBNegotiateContextValue::PreauthIntegrityCapabilities(pic) => {
                    pic.hash_algorithms.contains(&HashAlgorithm::Sha512)
                }
                _ => false,
            })
        {
            return Err("a non-SHA-512 preauth integrity hash algorithm is supplied".into());
        }

        let negotiate_state = SmbNegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_negotiate_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?,
        };
        log::trace!(
            "Negotiated SMB results: dialect={:?}, state={:?}",
            negotiate_state.selected_dialect,
            &negotiate_state
        );

        self.handler
            .borrow_mut()
            .negotiate_state
            .set(negotiate_state)
            .map_err(|_| "Negotiate state already set")?;

        Ok(())
    }

    pub fn negotiate(&mut self) -> Result<(), Box<dyn Error>> {
        self.negotiate_smb1()?;
        self.negotiate_smb2()?;
        log::info!("Negotiation successful");
        Ok(())
    }

    pub fn authenticate(
        self: &mut SMBClient,
        user_name: String,
        password: String,
    ) -> Result<SMBSession, Box<dyn Error>> {
        let mut session = SMBSession::new(self.handler.clone());

        session.setup(user_name, password)?;

        Ok(session)
    }
}

/// This struct is the internal message handler for the SMB client.
pub struct SMBClientMessageHandler {
    client_guid: u128,
    netbios_client: NetBiosClient,
    current_message_id: u64,

    preauth_hash: Option<PreauthHashState>,

    // Negotiation-related state.
    negotiate_state: OnceCell<SmbNegotiateState>,
}

impl SMBClientMessageHandler {
    fn new() -> SMBClientMessageHandler {
        SMBClientMessageHandler {
            client_guid: rand::rngs::OsRng.gen(),
            netbios_client: NetBiosClient::new(),
            negotiate_state: OnceCell::new(),
            current_message_id: 0,
            preauth_hash: None,
        }
    }

    /// Calculate preauth integrity hash value, if required.
    fn step_preauth_hash(&mut self, raw: &NetBiosTcpMessage) {
        if let Some(preauth_hash) = self.preauth_hash.take() {
            // If already finished -- do nothing.
            if let PreauthHashState::Finished(_) = preauth_hash {
                return;
            }
            // Otherwise, update the hash!
            self.preauth_hash = Some(preauth_hash.next(&raw.content));
        }
    }

    pub fn finalize_preauth_hash(&mut self) -> PreauthHashValue {
        self.preauth_hash = Some(self.preauth_hash.take().unwrap().finish());
        match self.preauth_hash.take().unwrap() {
            PreauthHashState::Finished(hash) => hash,
            _ => panic!("Preauth hash not finished"),
        }
    }

    pub fn negotiate_state(&self) -> Option<&SmbNegotiateState> {
        self.negotiate_state.get()
    }
}

impl SMBMessageHandler for SMBClientMessageHandler {
    fn send(
        &mut self,
        mut msg: OutgoingSMBMessage,
    ) -> Result<SendMessageResult, Box<(dyn std::error::Error + 'static)>> {
        self.current_message_id += 1;
        // TODO: Add assertion in the struct regarding the selected dialect!
        let priority_value = match self.negotiate_state.get() {
            Some(negotiate_state) => match negotiate_state.selected_dialect {
                SMBDialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        msg.message.header.message_id = self.current_message_id;
        msg.message.header.flags = msg.message.header.flags.with_priority_mask(priority_value);
        msg.message.header.credit_charge = 1;
        msg.message.header.credit_request = 1;

        let is_signed_set = msg.message.header.flags.signed();

        let mut header_copy = msg.message.header.clone();
        let content = NetBiosMessageContent::SMB2Message(msg.message);
        let mut raw_message_result = NetBiosTcpMessage::build(&content)?;
        if let Some(mut signer) = msg.signer.take() {
            assert!(is_signed_set);
            signer.sign_message(&mut header_copy, &mut raw_message_result)?;
        };

        self.step_preauth_hash(&raw_message_result);
        let hash = match msg.finalize_preauth_hash {
            true => Some(self.finalize_preauth_hash()),
            false => None,
        };

        self.netbios_client.send_raw(raw_message_result)?;

        Ok(SendMessageResult::new(hash.clone()))
    }

    fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        let raw = self.netbios_client.recieve_bytes()?;
        self.step_preauth_hash(&raw);
        let netbios_message = raw.parse()?;
        let smb2_message = match netbios_message {
            NetBiosMessageContent::SMB2Message(smb2_message) => Some(smb2_message),
            _ => None,
        }
        .ok_or("Expected SMB2 message")?;
        // TODO: FIX COMMAND RECEIVE MATCHING!
        // if smb2_message.header.command != command {
        //     return Err("Unexpected SMB2 command".into());
        // };
        if !smb2_message.header.flags.server_to_redir() {
            return Err("Unexpected SMB2 message direction (Not a response)".into());
        }
        // TODO: Implement this mechanism more wisely.
        // if require_success && smb2_message.header.status != SMB2Status::Success as u32 {
        //     return Err("SMB2 message status is not success".into());
        // }
        Ok(IncomingSMBMessage {
            message: smb2_message,
            raw,
        })
    }
}
