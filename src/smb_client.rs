use binrw::prelude::*;
use modular_bitfield::prelude::*;
use rand::Rng;
use sha2::{Sha512, Digest};
use sspi::{AuthIdentity, Secret, Username};
use core::panic;
use std::{cell::{OnceCell, RefCell}, error::Error, fmt::Display};

use crate::{
    authenticator::GssAuthenticator, msg_handler::{IncomingSMBMessage, OutgoingSMBMessage, SMBMessageHandler}, netbios_client::NetBiosClient, packets::{
        netbios::{NetBiosMessageContent, NetBiosTcpMessage},
        smb1::SMB1NegotiateMessage,
        smb2::{
            header::{SMB2Command, SMB2Status},
            message::{SMB2Message, SMBMessageContent},
            negotiate::{HashAlgorithm, SMBDialect, SMBNegotiateContextType, SMBNegotiateContextValue, SMBNegotiateRequest, SMBNegotiateResponseDialect, SigningAlgorithmId},
            session::SMB2SessionSetupRequest,
        },
    }, smb_session::SMBSession
};

enum PreauthHashState {
    NotStarted,
    InProgress([u8; 64]),
    Finished([u8; 64]),
}

struct SmbNegotiateState {
    server_guid: u128,

    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,

    gss_negotiate_token: Vec<u8>,

    selected_dialect: SMBDialect
}

pub struct SMBClient {
    client_guid: u128,
    netbios_client: NetBiosClient,
    current_message_id: u64,

    preauth_hash: PreauthHashState,

    // Negotiation-related state.
    negotiate_state: OnceCell<SmbNegotiateState>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
struct NonceSuffixFlags {
    is_server: bool,
    is_cancel: bool,
    zero: B30
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
            current_message_id: 0,
            preauth_hash: PreauthHashState::NotStarted,
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        self.netbios_client.connect(address)
    }

    fn negotiate_smb1(&mut self) -> Result<(), Box<dyn Error>> {
        // 1. Send SMB1 negotiate request
        self.netbios_client
            .send(NetBiosMessageContent::SMB1Message(
                SMB1NegotiateMessage::new(),
            ))?;

        // 2. Expect SMB2 negotiate response
        let smb2_response = self.receive()?;
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
        // Start preauth hash.
        self.preauth_hash = PreauthHashState::InProgress([0; 64]);

        // Send SMB2 negotiate request
        let neg_req = OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest::new(self.client_guid))
        ));
        self.send(neg_req)?;
        
        let smb2_response_raw = self.receive()?;

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
        if !context_list.iter()
            .any(|context| match &context.data {
                SMBNegotiateContextValue::SigningCapabilities(sc) => sc.signing_algorithms.contains(&SigningAlgorithmId::AesCmac),
                _ => false
            }) {
                return Err("AES-CMAC signing algorithm is not supported".into());
            }

        // Make sure preauth integrity capability is SHA-512.
        if !context_list.iter()
        .filter(|context| context.context_type == SMBNegotiateContextType::PreauthIntegrityCapabilities)
            .all(|context| match &context.data {
                SMBNegotiateContextValue::PreauthIntegrityCapabilities(pic) => pic.hash_algorithms.contains(&HashAlgorithm::Sha512),
                _ => false
            }) {
                return Err("a non-SHA-512 preauth integrity hash algorithm is supplied".into());
            }

        let negotiate_state = SmbNegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_negotiate_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?
        };

        self.negotiate_state
            .set(negotiate_state)
            .map_err(|_| "Negotiate state already set")?;

        Ok(())
    }

    pub fn negotiate(&mut self) -> Result<(), Box<dyn Error>> {
        self.negotiate_smb1()?;
        self.negotiate_smb2()
    }

    /// Calculate preauth integrity hash value, if required.
    fn step_preauth_hash(&mut self, raw: &NetBiosTcpMessage) {
        if let PreauthHashState::Finished(_) = self.preauth_hash {
            return;
        }

        let prev = match &self.preauth_hash {
            PreauthHashState::InProgress(hash) => hash,
            PreauthHashState::NotStarted => &[0; 64],
            _ => panic!()
        };
        let mut hasher = Sha512::new();
        hasher.update(&prev);
        hasher.update(&raw.content);
        // Update current state.
        self.preauth_hash = PreauthHashState::InProgress(hasher.finalize().into());
    }

    pub fn authenticate(
        self: &mut SMBClient,
        user_name: String,
        password: String,
    ) -> Result<SMBSession, Box<dyn Error>> {
        let negotate_state = self
            .negotiate_state
            .get()
            .ok_or(SmbClientNotConnectedError)?;
        let identity = AuthIdentity {
            username: Username::new(&user_name, Some("WORKGROUP"))?,
            password: Secret::new(password),
        };
        let (mut authenticator, next_buf) =
            GssAuthenticator::build(&negotate_state.gss_negotiate_token, identity)?;

        let request = OutgoingSMBMessage::new(SMB2Message::new(SMBMessageContent::SMBSessionSetupRequest(
            SMB2SessionSetupRequest::new(next_buf),
        )));
        self.send(request)?;
        // response hash is processed later, in the loop.
        let response = self.receive()?;
        if response.message.header.status != SMB2Status::MoreProcessingRequired as u32 {
            return Err("Expected STATUS_MORE_PROCESSING_REQUIRED".into());
        }
        let session = SMBSession::new(response.message.header.session_id, RefCell::new(self as &dyn SMBMessageHandler));

        let mut response = Some(response);
        while !authenticator.is_authenticated()? {
            // If there's a response to process, do so.
            let last_setup_response = match response.as_ref() {
                Some(response) => Some(
                    match &response.message.content {
                        SMBMessageContent::SMBSessionSetupResponse(response) => Some(response),
                        _ => None,
                    }
                    .unwrap(),
                ),
                None => None,
            };

            let next_buf = match last_setup_response.as_ref() {
                Some(response) => {
                    authenticator.next(&response.buffer)?
                },
                None => authenticator.next(&vec![])?,
            };

            response = match next_buf {
                Some(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let request = OutgoingSMBMessage::new(SMB2Message::new(SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(
                        next_buf,
                    ))));
                    self.send(request)?;

                    // Keys exchanged? We can set-up the session!
                    if authenticator.keys_exchanged() && !session.is_set_up() {
                        // Derive keys and set-up the final session.
                        let ntlm_key = authenticator.session_key()?.to_vec();
                        // Lock preauth hash, we're done with it.
                        let preauth_hash = match self.preauth_hash {
                            PreauthHashState::InProgress(hash) => hash,
                            _ => panic!()
                        };
                        self.preauth_hash = PreauthHashState::Finished(preauth_hash);
                        // Derive signing key, and set-up the session.
                        session.setup(&ntlm_key, preauth_hash)?;
                    }

                    let response = self.receive()?;

                    Some(response)
                },
                None => None,
            };
        }

        Ok(())
    }
}

impl SMBMessageHandler for SMBClient {
    fn send(&mut self, mut msg: OutgoingSMBMessage) -> Result<(), Box<dyn std::error::Error>> {
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

        let mut header_copy = msg.message.header.clone();
        let content = NetBiosMessageContent::SMB2Message(msg.message);
        let mut raw_message_result = NetBiosTcpMessage::build(&content)?;
        if let Some(mut signer) = msg.signer.take() {
            signer.sign_message(&mut header_copy, &mut raw_message_result)?;
        };
        
        self.step_preauth_hash(&raw_message_result);
        
        if let PreauthHashState::InProgress(hash) = &mut self.preauth_hash {
        } else if let PreauthHashState::NotStarted = self.preauth_hash {
            return Err("Preauth hash not started".into());
        }

        self.netbios_client.send_raw(raw_message_result)
    }

    fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        let raw = self.netbios_client.recieve_bytes()?;
        self.step_preauth_hash(&raw);
        let netbios_message = raw.parse()?;
        let mut smb2_message = match netbios_message {
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
        Ok(IncomingSMBMessage{ message: smb2_message , raw})
    }
}

impl Drop for SMBClient {
    fn drop(&mut self) {
        // TODO: - Close any trees open & logoff before closing the TCP stream.
    }
}