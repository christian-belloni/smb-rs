use crate::compression::{Compressor, Decompressor};

use super::negotiation_state::SmbNegotiateState;
use super::netbios_client::NetBiosClient;
use super::preauth_hash::*;
use crate::packets::guid::Guid;
use crate::{
    crypto,
    msg_handler::*,
    packets::{
        netbios::{NetBiosMessageContent, NetBiosTcpMessage},
        smb1::SMB1NegotiateMessage,
        smb2::{header::*, message::*, negotiate::*, plain::*},
    },
    session::Session,
};
use binrw::prelude::*;
use core::panic;
use std::{cell::OnceCell, error::Error, fmt::Display, io::Cursor};

pub struct Connection {
    handler: HandlerReference<ClientMessageHandler>,
}

#[derive(Debug, Clone)]
pub struct SmbClientNotConnectedError;

impl Display for SmbClientNotConnectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMB client is not connected")
    }
}

impl Error for SmbClientNotConnectedError {}

impl Connection {
    pub fn new() -> Connection {
        Connection {
            handler: HandlerReference::new(ClientMessageHandler::new()),
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
        let smb2_response = self.handler.recv(Command::Negotiate)?;
        let smb2_negotiate_response = match smb2_response.message.content {
            Content::NegotiateResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        // 3. Make sure dialect is smb2*
        if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb02Wildcard {
            return Err("Unexpected SMB2 dialect revision".into());
        }
        Ok(())
    }

    fn negotiate_smb2(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Negotiating SMB2");
        // Start preauth hash.
        self.handler.borrow_mut().preauth_hash = Some(PreauthHashState::default());

        // Send SMB2 negotiate request
        let client_guid = self.handler.borrow().client_guid;
        let response = self
            .handler
            .send_recv(Content::NegotiateRequest(NegotiateRequest::new(
                "AVIV-MBP".to_string(),
                client_guid,
                crypto::SIGNING_ALGOS.into(),
                crypto::ENCRYPTING_ALGOS.to_vec(),
            )))?;

        let smb2_negotiate_response = match response.message.content {
            Content::NegotiateResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        // well, only 3.1 is supported for starters.
        if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb0311 {
            return Err("Unexpected SMB2 dialect revision".into());
        }

        if let None = smb2_negotiate_response.negotiate_context_list {
            return Err("Negotiate context list is missing".into());
        }

        // TODO: Support non-SMB 3.1.1 dialects. (no contexts)
        let selected_signing_algo: SigningAlgorithmId =
            smb2_negotiate_response.get_signing_algo().unwrap();
        if !crypto::SIGNING_ALGOS.contains(&selected_signing_algo) {
            return Err(
                format!("Unsupported signing algorithm {:?}", selected_signing_algo).into(),
            );
        }

        // Make sure preauth integrity capability is SHA-512, if it exists in response:
        if let Some(algos) = smb2_negotiate_response.get_preauth_integrity_algos() {
            if !algos.contains(&HashAlgorithm::Sha512) {
                return Err("SHA-512 preauth integrity not supported".into());
            }
        }

        let compression = smb2_negotiate_response.get_compression().unwrap();
        let compressor = Compressor::new(
            compression.compression_algorithms.clone(),
            compression.flags.chained(),
        );
        let decompressor = Decompressor::new();

        let negotiate_state = SmbNegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_negotiate_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?,
            signing_algo: selected_signing_algo,
            compressor: Some(compressor),
            decompressor: Some(decompressor),
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
        self: &mut Connection,
        user_name: String,
        password: String,
    ) -> Result<Session, Box<dyn Error>> {
        let mut session = Session::new(self.handler.clone());

        session.setup(user_name, password)?;

        Ok(session)
    }
}

/// This struct is the internal message handler for the SMB client.
pub struct ClientMessageHandler {
    client_guid: Guid,
    netbios_client: NetBiosClient,
    current_message_id: u64,
    credits_balance: u16,

    preauth_hash: Option<PreauthHashState>,

    // Negotiation-related state.
    negotiate_state: OnceCell<SmbNegotiateState>,
}

impl ClientMessageHandler {
    fn new() -> ClientMessageHandler {
        ClientMessageHandler {
            client_guid: Guid::gen(),
            netbios_client: NetBiosClient::new(),
            negotiate_state: OnceCell::new(),
            current_message_id: 0,
            credits_balance: 1,
            preauth_hash: None,
        }
    }

    /// Calculate preauth integrity hash value, if required.
    fn step_preauth_hash(&mut self, raw: &Vec<u8>) {
        if let Some(preauth_hash) = self.preauth_hash.take() {
            // If already finished -- do nothing.
            if let PreauthHashState::Finished(_) = preauth_hash {
                return;
            }
            // Otherwise, update the hash!
            self.preauth_hash = Some(preauth_hash.next(&raw));
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

    /// Gets an OutgoingMessage ready for sending, performs crypto operations, and returns the
    /// final bytes to be sent.
    fn tranform_outgoing(
        &mut self,
        mut msg: OutgoingMessage,
    ) -> Result<NetBiosTcpMessage, Box<dyn Error>> {
        let should_encrypt = msg.encryptor.is_some();
        let should_sign = msg.signer.is_some() && !should_encrypt;
        let is_signed_set = msg.message.header.flags.signed();
        let set_session_id = msg.message.header.session_id;

        // 1. Sign
        let mut data = {
            let mut data = Vec::new();
            msg.message.write(&mut Cursor::new(&mut data))?;

            // 0. Update preauth hash as needed.
            self.step_preauth_hash(&data);
            if should_sign {
                debug_assert!(!should_encrypt && is_signed_set);
                let mut header_copy = msg.message.header.clone();
                if let Some(mut signer) = msg.signer.take() {
                    signer.sign_message(&mut header_copy, &mut data)?;
                };
            };
            data
        };

        // 2. Compress
        data = {
            if msg.compress && data.len() > 1024 {
                if let Some(compressor) = self.negotiate_state().unwrap().compressor.as_ref() {
                    let compressed = compressor.compress(&data)?;
                    data.clear();
                    let mut cursor = Cursor::new(&mut data);
                    Message::Compressed(compressed).write(&mut cursor)?;
                };
            }
            data
        };

        // 3. Encrypt
        let data = {
            if let Some(mut encryptor) = msg.encryptor.take() {
                debug_assert!(should_encrypt && !should_sign);
                let encrypted = encryptor.encrypt_message(data, set_session_id)?;
                let mut cursor = Cursor::new(Vec::new());
                Message::Encrypted(encrypted).write(&mut cursor)?;
                cursor.into_inner()
            } else {
                data
            }
        };

        Ok(NetBiosTcpMessage::from_content_bytes(data)?)
    }

    /// Given a NetBiosTcpMessage, decrypts (if necessary), decompresses (if necessary) and returns the plain SMB2 message.
    fn transform_incoming(
        &mut self,
        netbios: NetBiosTcpMessage,
        options: &mut ReceiveOptions,
    ) -> Result<(PlainMessage, Vec<u8>, MessageForm), Box<dyn Error>> {
        let message = match netbios.parse_content()? {
            NetBiosMessageContent::SMB2Message(message) => Some(message),
            _ => None,
        }
        .ok_or("Expected SMB2 message")?;

        let mut form = MessageForm::default();

        // 1. Decrpt
        let (message, raw) = if let Message::Encrypted(encrypted_message) = &message {
            form.encrypted = true;
            match options.decryptor.take() {
                Some(mut decryptor) => decryptor.decrypt_message(&encrypted_message)?,
                None => return Err("Encrypted message received without decryptor".into()),
            }
        } else {
            (message, netbios.content)
        };

        // 2. Decompress
        debug_assert!(!matches!(message, Message::Encrypted(_)));
        let (message, raw) = if let Message::Compressed(compressed_message) = &message {
            form.compressed = true;
            match self.negotiate_state().unwrap().decompressor.as_ref() {
                Some(decompressor) => decompressor.decompress(compressed_message)?,
                None => return Err("Compressed message received without decompressor!".into()),
            }
        } else {
            (message, raw)
        };

        // unwrap Message::Plain from Message enum:
        let message = match message {
            Message::Plain(message) => message,
            _ => panic!("Unexpected message type"),
        };

        Ok((message, raw, form))
    }
}

impl MessageHandler for ClientMessageHandler {
    fn hsendo(
        &mut self,
        mut msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<(dyn std::error::Error + 'static)>> {
        self.current_message_id += 1;
        // TODO: Add assertion in the struct regarding the selected dialect!
        let priority_value = match self.negotiate_state.get() {
            Some(negotiate_state) => match negotiate_state.selected_dialect {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        msg.message.header.message_id = self.current_message_id;
        msg.message.header.flags = msg.message.header.flags.with_priority_mask(priority_value);
        msg.message.header.credit_charge = 1;
        msg.message.header.credit_request = 1;

        let finalize_hash_required = msg.finalize_preauth_hash;
        let final_message = self.tranform_outgoing(msg)?;
        self.netbios_client.send_raw(final_message)?;

        let hash = match finalize_hash_required {
            true => Some(self.finalize_preauth_hash()),
            false => None,
        };

        Ok(SendMessageResult::new(hash.clone()))
    }

    fn hrecvo(
        &mut self,
        mut options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let netbios = self.netbios_client.recieve_bytes()?;

        self.step_preauth_hash(&netbios.content);

        let (message, raw, form) = self.transform_incoming(netbios, &mut options)?;

        // Command matching (if needed).
        if let Some(cmd) = options.cmd {
            if message.header.command != cmd {
                return Err("Unexpected SMB2 command".into());
            }
        }

        // Direction matching.
        if !message.header.flags.server_to_redir() {
            return Err("Unexpected SMB2 message direction (Not a response)".into());
        }

        // Expected status matching.
        if message.header.status != options.status {
            if let Content::ErrorResponse(msg) = &message.content {
                return Err(
                    format!("SMB2 error response {:?}: {:?}", message.header.status, msg).into(),
                );
            }
            return Err(format!("Unexpected SMB2 status: {:?}", message.header.status).into());
        }

        // Credits handling. TODO: validate.
        self.credits_balance -= message.header.credit_charge;
        self.credits_balance += message.header.credit_request;

        Ok(IncomingMessage { message, raw, form })
    }
}
