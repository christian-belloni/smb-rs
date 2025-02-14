pub mod negotiation_state;
pub mod netbios_client;
pub mod preauth_hash;
pub mod transformer;
pub mod worker;

use crate::packets::guid::Guid;
use crate::Error;
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
    pub async fn connect(&mut self, address: &str) -> crate::Result<()> {
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
    ) -> crate::Result<Arc<ConnectionWorker>> {
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
            .ok_or(Error::InvalidMessage(
                "Expected Negotiate response.".to_string(),
            ))?;

            // 3. Make sure dialect is smb2*, message ID is 0.
            if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb02Wildcard {
                return Err(Error::InvalidMessage(
                    "Expected SMB2 wildcard dialect".to_string(),
                ));
            }
            if smb2_response.message.header.message_id != 0 {
                return Err(Error::InvalidMessage("Expected message ID 0".to_string()));
            }
        }

        Ok(ConnectionWorker::start(netbios_client).await?)
    }

    #[maybe_async]
    async fn negotiate_smb2(&mut self) -> crate::Result<()> {
        // Confirm that we're not already negotiated.
        if self.handler.negotiate_state().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

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
        .ok_or(Error::InvalidMessage(
            "Expected Negotiate response.".to_string(),
        ))?;

        // well, only 3.1 is supported for starters.
        if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb0311 {
            return Err(Error::UnsupportedDialect(
                smb2_negotiate_response.dialect_revision,
            ));
        }

        if let None = smb2_negotiate_response.negotiate_context_list {
            return Err(Error::InvalidMessage(
                "Expected negotiate context list".to_string(),
            ));
        }

        let signing_algo: SigningAlgorithmId = smb2_negotiate_response.get_signing_algo().unwrap();
        if !crypto::SIGNING_ALGOS.contains(&signing_algo) {
            return Err(Error::NegotiationError(
                "Unsupported signing algorithm received".into(),
            ));
        }

        // Make sure preauth integrity capability is SHA-512, if it exists in response:
        if let Some(algo) = smb2_negotiate_response.get_preauth_integrity_algo() {
            if !preauth_hash::SUPPORTED_ALGOS.contains(&algo) {
                return Err(Error::NegotiationError(
                    "Unsupported preauth integrity algorithm received".into(),
                ));
            }
        }

        // And verify that the encryption algorithm is supported.
        let encryption_cipher = smb2_negotiate_response.get_encryption_cipher().unwrap();
        if !crypto::ENCRYPTING_ALGOS.contains(&encryption_cipher) {
            return Err(Error::NegotiationError(
                "Unsupported encryption algorithm received".into(),
            ));
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

        self.handler.negotiate_state.set(negotiate_state).unwrap();

        Ok(())
    }

    /// Send negotiate messages, potentially
    #[maybe_async]
    async fn negotiate(
        &mut self,
        netbios_client: NetBiosClient,
        multi_protocol: bool,
    ) -> crate::Result<()> {
        if self.handler.negotiate_state().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        // Negotiate SMB1, Switch to SMB2
        let worker = self
            .negotiate_switch_to_smb2(netbios_client, multi_protocol)
            .await?;

        self.handler.worker.set(worker).unwrap();

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
    ) -> crate::Result<Session> {
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
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
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
            .ok_or(Error::InvalidState("Worker is uninitialized".into()))?
            .send(msg)
            .await?)
    }

    #[maybe_async]
    async fn recvo(&self, options: ReceiveOptions) -> crate::Result<IncomingMessage> {
        let msg = self
            .worker
            .get()
            .unwrap()
            .receive(options.msgid_filter)
            .await?;

        // Command matching (if needed).
        if let Some(cmd) = options.cmd {
            if msg.message.header.command != cmd {
                return Err(Error::UnexpectedCommand(msg.message.header.command));
            }
        }

        // Direction matching.
        if !msg.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }

        // Expected status matching.
        if msg.message.header.status != options.status {
            // Return error only if it is unexpected.
            if let Content::ErrorResponse(error_res) = msg.message.content {
                return Err(Error::RecievedErrorMessage(error_res));
            }
            return Err(Error::UnexpectedMessageStatus(msg.message.header.status));
        }

        // Credits handling. TODO: Make sure how this calculation behaves when error/edge cases.
        let diff = msg.message.header.credit_request - msg.message.header.credit_charge;
        self.credits_balance.fetch_add(diff, Ordering::Relaxed);

        Ok(msg)
    }
}
