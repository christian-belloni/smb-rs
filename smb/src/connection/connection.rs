
use super::negotiation_state::NegotiateState;
use super::netbios_client::NetBiosClient;
use super::preauth_hash::*;
use super::worker::ConnectionWorker;
use crate::packets::guid::Guid;
use crate::{
    crypto,
    msg_handler::*,
    packets::{
        netbios::NetBiosMessageContent,
        smb1::SMB1NegotiateMessage,
        smb2::{header::*, negotiate::*, plain::*},
    },
    session::Session,
};
use binrw::prelude::*;
use core::panic;
use maybe_async::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::{cell::OnceCell, error::Error, fmt::Display, io::Cursor};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

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

    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        log::debug!("Connecting to {}, multi-protocol negotiation.", address);
        self.handler
            .borrow_mut()
            .neg_mode
            .multi()?
            .connect(address)
            .await?;
        log::info!("Connected to {}.", address);
        self.mprot_negotiate().await?;
        Ok(())
    }

    #[maybe_async]
    async fn negotiate_smb1(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Negotiating SMB1");
        // 1. Send SMB1 negotiate request
        self.handler
            .borrow_mut()
            .neg_mode
            .multi()?
            .send(NetBiosMessageContent::SMB1Message(
                SMB1NegotiateMessage::new(),
            ))
            .await?;

        // 2. Expect SMB2 negotiate response
        let smb2_response = self.handler.recv(Command::Negotiate).await?;
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

    #[maybe_async]
    async fn negotiate_smb2(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Negotiating SMB2");
        // Send SMB2 negotiate request
        let client_guid = self.handler.borrow().client_guid;
        let response = self
            .handler
            .send_recv(Content::NegotiateRequest(NegotiateRequest::new(
                "AVIV-MBP".to_string(),
                client_guid,
                crypto::SIGNING_ALGOS.into(),
                crypto::ENCRYPTING_ALGOS.to_vec(),
            )))
            .await?;

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
        let signing_algo: SigningAlgorithmId = smb2_negotiate_response.get_signing_algo().unwrap();
        if !crypto::SIGNING_ALGOS.contains(&signing_algo) {
            return Err(format!("Unsupported signing algorithm {:?}", signing_algo).into());
        }

        // Make sure preauth integrity capability is SHA-512, if it exists in response:
        if let Some(algos) = smb2_negotiate_response.get_preauth_integrity_algos() {
            if !algos.contains(&HashAlgorithm::Sha512) {
                return Err("SHA-512 preauth integrity not supported".into());
            }
        }

        // And verify that the encryption algorithm is supported.
        let encryption_cipher = smb2_negotiate_response.get_encryption_cipher().unwrap();
        if !crypto::ENCRYPTING_ALGOS.contains(&encryption_cipher) {
            return Err(format!("Unsupported encryption algorithm {:?}", encryption_cipher).into());
        }

        let compression: Option<CompressionCaps> = match smb2_negotiate_response.get_compression() {
            Some(compression) => Some(compression.clone()),
            None => None,
        };

        let negotiate_state = NegotiateState {
            server_guid: smb2_negotiate_response.server_guid,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            gss_token: smb2_negotiate_response.buffer,
            selected_dialect: smb2_negotiate_response.dialect_revision.try_into()?,
            signing_algo,
            encryption_cipher,
            compression,
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

    /// Multi-protocol negotiation.
    #[maybe_async]
    async fn mprot_negotiate(&mut self) -> Result<(), Box<dyn Error>> {
        // Negotiate SMB1, Switch to SMB2
        self.negotiate_smb1().await?;

        // Upgrade connection backend to SMB2 worker
        {
            let handler = &mut self.handler.borrow_mut();
            // do ConnectionWorker::start() on Mprot/NetBiosClient and set to NegotiationMode::Smb2Neg
            let worker = ConnectionWorker::start(handler.neg_mode.take_multi().unwrap()).await?;
            handler.neg_mode = NegotiationMode::Smb2Neg(worker);
        }
        // Negotiate SMB2
        self.negotiate_smb2().await?;
        self.handler
            .borrow_mut()
            .neg_mode
            .smb2()
            .unwrap()
            .negotaite_complete(&self.handler.borrow().negotiate_state().unwrap())
            .await;
        log::info!("Negotiation successful");
        Ok(())
    }

    #[maybe_async]
    pub async fn authenticate(
        self: &mut Connection,
        user_name: String,
        password: String,
    ) -> Result<Session, Box<dyn Error>> {
        let mut session = Session::new(self.handler.clone());

        session.setup(user_name, password).await?;

        Ok(session)
    }
}

enum NegotiationMode {
    Mprot(Option<NetBiosClient>),
    Smb2Neg(Arc<ConnectionWorker>),
}

impl NegotiationMode {
    fn multi(&mut self) -> Result<&mut NetBiosClient, Box<dyn Error>> {
        match self {
            NegotiationMode::Mprot(client) => match client {
                Some(client) => Ok(client),
                None => {
                    return Err("Unexpected connection state".into());
                }
            },
            _ => Err("Unexpected connection state".into()),
        }
    }

    fn take_multi(&mut self) -> Result<NetBiosClient, Box<dyn Error>> {
        match self {
            NegotiationMode::Mprot(client) => match client.take() {
                Some(client) => Ok(client),
                None => {
                    return Err("Unexpected connection state".into());
                }
            },
            _ => Err("Unexpected connection state".into()),
        }
    }

    fn smb2(&mut self) -> Result<&mut Arc<ConnectionWorker>, Box<dyn Error>> {
        match self {
            NegotiationMode::Smb2Neg(worker) => Ok(worker),
            _ => Err("Unexpected connection state".into()),
        }
    }
}

/// This struct is the internal message handler for the SMB client.
pub struct ClientMessageHandler {
    client_guid: Guid,

    neg_mode: NegotiationMode,

    current_message_id: u64,
    credits_balance: u16,

    // Negotiation-related state.
    negotiate_state: OnceCell<NegotiateState>,
}

impl ClientMessageHandler {
    fn new() -> ClientMessageHandler {
        ClientMessageHandler {
            client_guid: Guid::gen(),
            neg_mode: NegotiationMode::Mprot(Some(NetBiosClient::new())),
            negotiate_state: OnceCell::new(),
            current_message_id: 0,
            credits_balance: 1,
        }
    }


    pub fn negotiate_state(&self) -> Option<&NegotiateState> {
        self.negotiate_state.get()
    }
}

impl MessageHandler for ClientMessageHandler {
    #[maybe_async]
    async fn hsendo(
        &self,
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

        Ok(self.neg_mode.smb2().unwrap().send(msg).await?)
    }

    #[maybe_async]
    async fn hrecvo(
        &self,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let msg = self
            .neg_mode
            .smb2()
            .unwrap()
            .receive(options.msgid_filter)
            .await?;

        // Command matching (if needed).
        if let Some(cmd) = options.cmd {
            if msg.message.header.command != cmd {
                return Err("Unexpected SMB2 command".into());
            }
        }

        // Direction matching.
        if !msg.message.header.flags.server_to_redir() {
            return Err("Unexpected SMB2 message direction (Not a response)".into());
        }

        // Expected status matching.
        if msg.message.header.status != options.status {
            if let Content::ErrorResponse(error_res) = &msg.message.content {
                return Err(format!(
                    "SMB2 error response {:?}: {:?}",
                    msg.message.header.status, error_res.error_data
                )
                .into());
            }
            return Err(format!("Unexpected SMB2 status: {:?}", msg.message.header.status).into());
        }

        // Credits handling. TODO: validate.
        self.credits_balance -= msg.message.header.credit_charge;
        self.credits_balance += msg.message.header.credit_request;

        Ok(msg)
    }
}
