use binrw::prelude::*;
use modular_bitfield::prelude::*;
use rand::Rng;
use sha2::{Sha512, Digest};
use sspi::{AuthIdentity, Secret, Username};
use std::{cell::OnceCell, error::Error, fmt::Display};

use crate::{
    authenticator::{GssAuthenticator}, netbios_client::{NetBiosClient}, packets::{
        netbios::{NetBiosMessageContent, NetBiosTcpMessage},
        smb1::SMB1NegotiateMessage,
        smb2::{
            header::{SMB2Command, SMB2HeaderFlags, SMB2Status},
            message::{SMB2Message, SMBMessageContent},
            negotiate::{HashAlgorithm, SMBDialect, SMBNegotiateContextType, SMBNegotiateContextValue, SMBNegotiateRequest, SMBNegotiateResponseDialect, SigningAlgorithmId},
            session::SMB2SessionSetupRequest, tree::SMB2TreeConnectRequest,
        },
    }, smb_session::SMBSession, smb_tree::SMBTree
};

struct SmbNegotiateState {
    server_guid: u128,

    max_transact_size: u32,
    max_read_size: u32,
    max_write_size: u32,

    gss_negotiate_token: Vec<u8>,

    selected_dialect: SMBDialect,

    negotiate_preauth_integrity_hash_value: [u8; 64],
}

pub struct SMBClient {
    client_guid: u128,
    netbios_client: NetBiosClient,
    current_message_id: u64,

    // Negotiation-related state.
    negotiate_state: OnceCell<SmbNegotiateState>,

    session_id: u64,
    session: Option<SMBSession>,
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
            session_id: 0,
            session: None,
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        self.netbios_client.connect(address)
    }

    fn receive_smb2(
        &mut self,
        command: SMB2Command,
        require_success: bool,
    ) -> Result<SMB2Message, Box<dyn Error>> {
        let raw = self.netbios_client.recieve_bytes()?;
        self.process_smb2(&raw, command, require_success)
    }

    fn recieve_smb2_raw(&mut self) -> Result<NetBiosTcpMessage, Box<dyn Error>> {
        self.netbios_client.recieve_bytes()
    }

    fn process_smb2(&self, 
        raw: &NetBiosTcpMessage, 
        command: SMB2Command,
        require_success: bool,
    ) -> Result<SMB2Message, Box<dyn Error>> {
        let netbios_message = raw.parse()?;
        let mut smb2_message = match netbios_message {
            NetBiosMessageContent::SMB2Message(smb2_message) => Some(smb2_message),
            _ => None,
        }
        .ok_or("Expected SMB2 message")?;
        if smb2_message.header.command != command {
            return Err("Unexpected SMB2 command".into());
        };
        if !smb2_message.header.flags.server_to_redir() {
            return Err("Unexpected SMB2 message direction (Not a response)".into());
        }
        if require_success && smb2_message.header.status != SMB2Status::Success as u32 {
            return Err("SMB2 message status is not success".into());
        }
        // Skip authentication is message ID is -1 or status is pending. (TODO: Encryption support!)
        if smb2_message.header.message_id != u64::MAX && smb2_message.header.status != SMB2Status::StatusPending as u32 {
            if let Some(session) = &self.session {
                // 1. Make sure the message is, indeed, signed.
                if !smb2_message.header.flags.signed() {
                    return Err("Expected signed SMB2 message".into());
                }
                // 2. Validate the signature.
                session.verify_signature(&mut smb2_message.header, &raw)?;
            }
        }
        Ok(smb2_message)
    }

    fn content_to_message(&mut self, content: SMBMessageContent) -> Result<NetBiosTcpMessage, Box<dyn Error>> {
        self.current_message_id += 1;
        // TODO: Add assertion in the struct regarding the selected dialect!
        let priority_value = match self.negotiate_state.get() {
            Some(negotiate_state) => match negotiate_state.selected_dialect {
                SMBDialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        let mut flags = SMB2HeaderFlags::new().with_priority_mask(priority_value);
        if let Some(session) = &self.session {
            flags.set_signed(session.signing_enabled());
        }
        let message_with_header = SMB2Message::new(
            content,
            self.current_message_id,
            1,
            1,
            flags,
            self.session_id,
        );
        let mut header_copy = message_with_header.header.clone();
        let content = NetBiosMessageContent::SMB2Message(message_with_header);
        let mut raw_message_result = NetBiosTcpMessage::build(&content)?;
        if let Some(session) = &self.session {
            if session.signing_enabled() {
                session.sign_message(&mut header_copy, &mut raw_message_result)?;
            }
        };
        // Update content of message with the new header.
        Ok(raw_message_result)
    }

    #[inline]
    fn send_raw(&mut self, raw: NetBiosTcpMessage) -> Result<(), Box<dyn Error>> {
        self.netbios_client.send_raw(raw)
    }

    fn send_and_receive_smb2(
        &mut self,
        message: SMBMessageContent,
        require_success: bool
    ) -> Result<SMB2Message, Box<dyn Error>> {
        let cmd = message.associated_cmd();
        let message = self.content_to_message(message)?;
        self.netbios_client
            .send_raw(message)?;
        self.receive_smb2(cmd, require_success)
    }

    fn negotiate_smb1(&mut self) -> Result<(), Box<dyn Error>> {
        // 1. Send SMB1 negotiate request
        self.netbios_client
            .send(NetBiosMessageContent::SMB1Message(
                SMB1NegotiateMessage::new(),
            ))?;

        // 2. Expect SMB2 negotiate response
        let smb2_response = self.receive_smb2(SMB2Command::Negotiate, true)?;
        let smb2_negotiate_response = match smb2_response.content {
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
        let mut current_hash: [u8; 64] = [0; 64];

        // Send SMB2 negotiate request
        let neg_req = self.content_to_message(SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest::new(self.client_guid)))?;
        Self::step_preauth_hash(&mut current_hash, &neg_req);
        self.send_raw(neg_req)?;
        
        let smb2_response_raw = self.recieve_smb2_raw()?;
        let smb2_response = self.process_smb2(&smb2_response_raw, SMB2Command::Negotiate, true)?;

        let smb2_negotiate_response = match smb2_response.content {
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

        Self::step_preauth_hash(&mut current_hash, &smb2_response_raw);

        let negotiate_state = SmbNegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_negotiate_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?,
            negotiate_preauth_integrity_hash_value: current_hash
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

    /// Calculate preauth integrity hash value.
    /// In client, SHA-512(SHA512(Request)|Response)
    fn step_preauth_hash(prev: &mut [u8; 64], raw: &NetBiosTcpMessage) {
        let mut hasher = Sha512::new();
        hasher.update(&prev);
        hasher.update(&raw.content);
        // finalize into prev:
        prev.copy_from_slice(&hasher.finalize());
    }

    pub fn authenticate(
        &mut self,
        user_name: String,
        password: String,
    ) -> Result<(), Box<dyn Error>> {
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
        
        // Preauth integrity hash, updated through the authentication process.
        let mut preauth_integrity_hash = self.negotiate_state.get().ok_or("No negotiate state!")?.negotiate_preauth_integrity_hash_value.clone();

        let request = self.content_to_message(SMBMessageContent::SMBSessionSetupRequest(
            SMB2SessionSetupRequest::new(next_buf),
        ))?;
        Self::step_preauth_hash(&mut preauth_integrity_hash, &request);
        self.send_raw(request)?;
        // response hash is processed later, in the loop.
        let response_raw = self.recieve_smb2_raw()?;
        let response = self.process_smb2(&response_raw, SMB2Command::SessionSetup, false)?;
        if response.header.status != SMB2Status::MoreProcessingRequired as u32 {
            return Err("Expected STATUS_MORE_PROCESSING_REQUIRED".into());
        }
        self.session_id = response.header.session_id;

        let mut response = Some((response, response_raw));
        while !authenticator.is_authenticated()? {
            // If there's a response to process, do so.
            let last_setup_response = match response.as_ref() {
                Some(response) => Some(
                    match &response.0.content {
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
                    Self::step_preauth_hash(&mut preauth_integrity_hash, &response.unwrap().1);
                    let request = SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(
                        next_buf,
                    ));
                    let request = self.content_to_message(request)?;
                    Self::step_preauth_hash(&mut preauth_integrity_hash, &request);
                    self.send_raw(request)?;
                    let response_raw = self.recieve_smb2_raw()?;

                    // Keys exchanged? We can set-up the session!
                    if authenticator.keys_exchanged() {
                        // Derive keys and set-up the final session.
                        let ntlm_key = authenticator.session_key()?.to_vec();
                        self.session = Some(SMBSession::build(&ntlm_key, preauth_integrity_hash)?);
                    }

                    Some((self.process_smb2(&response_raw, SMB2Command::SessionSetup, false)?, response_raw))
                },
                None => None,
            };
        }

        Ok(())
    }

    pub fn tree_connect(&mut self, name: String) -> Result<SMBTree, Box<dyn Error>> {
        let response = self.send_and_receive_smb2(SMBMessageContent::SMBTreeConnectRequest(
            SMB2TreeConnectRequest::new(name.as_bytes().to_vec()),
        ), true)?;

        let _response = match response.content {
            SMBMessageContent::SMBTreeConnectResponse(response) => Some(response),
            _ => None,
        }.unwrap();

        Ok(SMBTree::new(response.header.tree_id))
    }
}

impl Drop for SMBClient {
    fn drop(&mut self) {
        // TODO: - Close any trees open & logoff before closing the TCP stream.
    }
}