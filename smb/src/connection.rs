pub mod negotiation_state;
pub mod netbios_client;
pub mod preauth_hash;
pub mod transformer;
pub mod worker;

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
use maybe_async::*;
use negotiation_state::NegotiateState;
use netbios_client::NetBiosClient;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(not(feature = "async"))]
use std::{cell::OnceCell, sync::Mutex};
use thiserror::Error;
#[cfg(feature = "async")]
use tokio::sync::OnceCell;
pub use transformer::TransformError;
use worker::ConnectionWorker;

pub struct Connection {
    handler: HandlerReference<ClientMessageHandler>,
}

impl Connection {
    pub fn new() -> Connection {
        Connection {
            handler: HandlerReference::new(ClientMessageHandler::new()),
        }
    }

    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> Result<(), crate::Error> {
        let mut netbios_client = NetBiosClient::new();

        log::debug!("Connecting to {}, multi-protocol negotiation.", address);
        netbios_client.connect(address).await?;

        log::info!("Connected to {}. Negotiating.", address);
        self.negotiate(netbios_client, true).await?;

        Ok(())
    }

    #[maybe_async]
    async fn negotiate_switch_to_smb2(
        &mut self,
        mut netbios_client: NetBiosClient,
        negotiate_smb1: bool,
    ) -> Result<Arc<ConnectionWorker>, crate::Error> {
        // Multi-protocol negotiation.
        if negotiate_smb1 {
            log::debug!("Negotiating multi-protocol");
            // 1. Send SMB1 negotiate request
            netbios_client
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
            .ok_or(crate::Error::InvalidMessage(
                "Expected Negotiate response.".to_string(),
            ))?;

            // 3. Make sure dialect is smb2*, message ID is 0.
            if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb02Wildcard {
                return Err(crate::Error::InvalidMessage(
                    "Expected SMB2 wildcard dialect".to_string(),
                ));
            }
            if smb2_response.message.header.message_id != 0 {
                return Err(crate::Error::InvalidMessage("Expected message ID 0".to_string()));
            }
        }

        Ok(ConnectionWorker::start(netbios_client).await?)
    }

    #[maybe_async]
    async fn negotiate_smb2(&mut self) -> Result<(), crate::Error> {
        log::debug!("Negotiating SMB2");
        // Send SMB2 negotiate request
        let client_guid = self.handler.client_guid;
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
        .ok_or("Unexpected SMB2 negotiate response")?;

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
            .negotiate_state
            .set(negotiate_state)
            .map_err(|_| "Negotiate state already set")?;

        Ok(())
    }

    /// Send negotiate messages, potentially
    #[maybe_async]
    async fn negotiate(
        &mut self,
        netbios_client: NetBiosClient,
        multi_protocol: bool,
    ) -> Result<(), crate::Error> {
        // Negotiate SMB1, Switch to SMB2
        let worker = self
            .negotiate_switch_to_smb2(netbios_client, multi_protocol)
            .await?;

        self.handler.worker.set(worker)?;

        // Negotiate SMB2
        self.negotiate_smb2().await?;
        self.handler
            .worker
            .get()
            .ok_or("Worker is uninitialized")
            .unwrap()
            .negotaite_complete(&self.handler.negotiate_state().unwrap())
            .await;
        log::info!("Negotiation successful");
        Ok(())
    }

    #[maybe_async]
    pub async fn authenticate(
        self: &mut Connection,
        user_name: String,
        password: String,
    ) -> Result<Session, crate::Error> {
        let mut session = Session::new(self.handler.clone());

        session.setup(user_name, password).await?;

        Ok(session)
    }
}

/// This struct is the internal message handler for the SMB client.
pub struct ClientMessageHandler {
    client_guid: Guid,

    worker: OnceCell<Arc<ConnectionWorker>>,

    current_message_id: AtomicU64,
    credits_balance: AtomicU16,

    // Negotiation-related state.
    negotiate_state: OnceCell<NegotiateState>,
}

impl ClientMessageHandler {
    fn new() -> ClientMessageHandler {
        ClientMessageHandler {
            client_guid: Guid::gen(),
            worker: OnceCell::new(),
            negotiate_state: OnceCell::new(),
            current_message_id: AtomicU64::new(0),
            credits_balance: AtomicU16::new(1), // TODO: Validate!
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
        // message id += 1, atomic.
        msg.message.header.message_id = self.current_message_id.fetch_add(1, Ordering::Relaxed);
        // TODO: Add assertion in the struct regarding the selected dialect!
        let priority_value = match self.negotiate_state.get() {
            Some(negotiate_state) => match negotiate_state.selected_dialect {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        msg.message.header.flags = msg.message.header.flags.with_priority_mask(priority_value);
        msg.message.header.credit_charge = 1;
        msg.message.header.credit_request = 1;

        Ok(self
            .worker
            .get()
            .ok_or("Worker is uninitialized!")?
            .send(msg)
            .await?)
    }

    #[maybe_async]
    async fn hrecvo(
        &self,
        options: ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let msg = self
            .worker
            .get()
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
                    msg.message.header.status, crate::Error_res.error_data
                )
                .into());
            }
            return Err(format!("Unexpected SMB2 status: {:?}", msg.message.header.status).into());
        }

        // Credits handling. TODO: Make sure how this calculation behaves when error/edge cases.
        let diff = msg.message.header.credit_request - msg.message.header.credit_charge;
        self.credits_balance.fetch_add(diff, Ordering::Relaxed);

        Ok(msg)
    }
}
