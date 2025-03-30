//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::connection::connection_info::ConnectionInfo;
use crate::connection::worker::Worker;
use crate::sync_helpers::*;
use crate::{
    connection::ConnectionMessageHandler,
    crypto::KeyToDerive,
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
        SendMessageResult,
    },
    packets::smb2::*,
    tree::Tree,
    Error,
};
use binrw::prelude::*;
use maybe_async::*;
use sspi::{AuthIdentity, Secret, Username};
use std::sync::Arc;
type Upstream = HandlerReference<ConnectionMessageHandler>;

mod authenticator;
mod encryptor_decryptor;
mod signer;
mod state;

use authenticator::GssAuthenticator;
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;
pub use state::SessionState;

pub struct Session {
    handler: HandlerReference<SessionMessageHandler>,
    conn_info: Arc<ConnectionInfo>,
}

impl Session {
    /// Sets up the session with the specified username and password.
    #[maybe_async]
    pub async fn setup(
        user_name: &str,
        password: String,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session> {
        let req_security_mode = SessionSecurityMode::new().with_signing_enabled(true);

        let mut session_state = Arc::new(Mutex::new(SessionState::default()));

        log::debug!("Setting up session for user {}.", user_name);

        let username = Username::new(user_name, Some("WORKGROUP")).map_err(|e| {
            Error::UsernameError(format!("Failed to create username: {}", e.to_string()))
        })?;

        // Build the authenticator.
        let (mut authenticator, next_buf) = {
            let identity = AuthIdentity {
                username,
                password: Secret::new(password),
            };
            GssAuthenticator::build(&conn_info.negotiation.auth_buffer, identity)?
        };

        let request = OutgoingMessage::new(PlainMessage::new(Content::SessionSetupRequest(
            SessionSetupRequest::new(next_buf, req_security_mode),
        )));

        // response hash is processed later, in the loop.
        let init_response = upstream
            .sendo_recvo(
                request,
                ReceiveOptions::new().status(&[Status::MoreProcessingRequired, Status::Success]),
            )
            .await?;

        let handler = SessionMessageHandler::new(upstream, session_state.clone());
        // Set session id.
        *handler.session_id.write().await? = init_response.message.header.session_id;
        session_state.lock().await?.session_id = init_response.message.header.session_id;

        let setup_result = if init_response.message.header.status == Status::Success as u32 {
            unimplemented!()
        } else {
            Self::setup_more_processing(
                &mut authenticator,
                init_response,
                &session_state,
                req_security_mode,
                &handler,
                conn_info,
            )
            .await
        };

        let flags = match setup_result {
            Ok(flags) => flags,
            Err(e) => {
                // Make sure the session is removed.
                if let Err(x) = SessionState::invalidate(&session_state).await {
                    log::debug!("Failed to invalidate session: {}!", x);
                }
                // Notify the worker that the session is invalid.
                if let Err(x) = upstream
                    .worker()
                    .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
                    .session_ended(*handler.session_id.read().await?)
                    .await
                {
                    log::debug!("Failed to notify worker about session end: {}!", x);
                }
                return Err(e);
            }
        };

        log::info!("Session setup complete.");
        SessionState::set_flags(&mut session_state, flags, &conn_info).await?;

        let session = Session {
            handler,
            conn_info: conn_info.clone(),
        };

        Ok(session)
    }

    #[maybe_async]
    pub async fn setup_more_processing(
        authenticator: &mut GssAuthenticator,
        init_response: IncomingMessage,
        session_state: &Arc<Mutex<SessionState>>,
        req_security_mode: SessionSecurityMode,
        handler: &HandlerReference<SessionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<SessionFlags> {
        let mut response = Some(init_response);
        let mut flags = None;

        // While there's a response to process, do so.
        while !authenticator.is_authenticated()? {
            let last_setup_response = match response.as_ref() {
                Some(response) => Some(
                    match &response.message.content {
                        Content::SessionSetupResponse(response) => Some(response),
                        _ => None,
                    }
                    .unwrap(),
                ),
                None => None,
            };

            flags = match last_setup_response {
                Some(response) => Some(response.session_flags),
                None => flags,
            };

            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer)?,
                None => authenticator.next(&vec![])?,
            };

            response = match next_buf {
                Some(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let mut request =
                        OutgoingMessage::new(PlainMessage::new(Content::SessionSetupRequest(
                            SessionSetupRequest::new(next_buf, req_security_mode),
                        )));
                    let is_about_to_finish = authenticator.keys_exchanged()
                        && !SessionState::is_set_up(&session_state).await?;
                    request.finalize_preauth_hash = is_about_to_finish;
                    let result = handler.sendo(request).await?;

                    // If keys are exchanged, set them up, to enable validation of next response!
                    if is_about_to_finish {
                        let ntlm_key: KeyToDerive = authenticator.session_key()?;

                        SessionState::set(
                            &session_state,
                            &ntlm_key,
                            &result.preauth_hash,
                            conn_info,
                        )
                        .await?;
                        log::trace!("Session signing key set.");

                        handler
                            .upstream
                            .handler
                            .worker()
                            .ok_or_else(|| {
                                Error::InvalidState("Worker not available!".to_string())
                            })?
                            .session_started(session_state.clone())
                            .await?;
                        log::trace!("Session inserted into worker.");
                    }

                    let expected_status = if is_about_to_finish {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };
                    let response = handler
                        .recvo(ReceiveOptions::new().status(&[expected_status]).to(result))
                        .await?;
                    Some(response)
                }
                None => None,
            };
        }

        flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))
    }

    /// Connects to the specified tree using the current session.
    #[maybe_async]
    pub async fn tree_connect(&self, name: &str) -> crate::Result<Tree> {
        Tree::connect(name, &self.handler, &self.conn_info).await
    }
}

pub struct SessionMessageHandler {
    session_id: RwLock<u64>,
    upstream: Upstream,

    session_state: Arc<Mutex<SessionState>>,
}

impl SessionMessageHandler {
    pub fn new(
        upstream: &Upstream,
        session_state: Arc<Mutex<SessionState>>,
    ) -> HandlerReference<SessionMessageHandler> {
        HandlerReference::new(SessionMessageHandler {
            session_id: RwLock::new(0),
            upstream: upstream.clone(),
            session_state,
        })
    }

    #[maybe_async]
    pub async fn should_sign(&self) -> crate::Result<bool> {
        SessionState::signing_enabled(&self.session_state).await
    }

    #[maybe_async]
    pub async fn should_encrypt(&self) -> crate::Result<bool> {
        SessionState::encryption_enabled(&self.session_state).await
    }

    #[maybe_async]
    async fn logoff(&self) -> crate::Result<()> {
        if *self.session_id.read().await? == 0 {
            log::trace!("Session not set up/already logged-off.");
            return Ok(());
        }

        if !SessionState::is_set_up(&self.session_state).await? {
            log::trace!("Session not set up/already logged-off.");
            return Ok(());
        }

        log::debug!("Logging off session.");

        let _response = self
            .send_recv(Content::LogoffRequest(Default::default()))
            .await?;

        // Reset session ID and keys.
        SessionState::invalidate(&self.session_state).await?;
        let session_id = {
            let mut session_id_ref = self.session_id.write().await?;
            let session_id = *session_id_ref;
            *session_id_ref = 0;
            session_id
        };
        self.upstream
            .handler
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(session_id)
            .await?;

        log::info!("Session logged off.");

        Ok(())
    }

    #[cfg(feature = "async")]
    #[maybe_async]
    pub async fn logoff_async(&mut self) {
        self.logoff().await.unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

impl MessageHandler for SessionMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        if *self.session_id.read().await? == 0
            || !SessionState::is_set_up(&self.session_state).await?
        {
            return Err(
                Error::InvalidState("Session is invalid or not set up!".to_string()).into(),
            );
        }

        // Encrypt?
        if self.should_encrypt().await? {
            msg.encrypt = true;
        }
        // Sign instead?
        else if self.should_sign().await? {
            msg.message.header.flags.set_signed(true);
        }
        msg.message.header.session_id = *self.session_id.read().await?;
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        if *self.session_id.read().await? == 0
            || !SessionState::is_set_up(&self.session_state).await?
        {
            return Err(Error::InvalidState(
                "Session is invalid or not set up!".to_string(),
            ));
        }

        let incoming = self.upstream.recvo(options).await?;
        // Make sure that it's our session.
        if incoming.message.header.session_id == 0 {
            return Err(Error::InvalidMessage(
                "No session ID in message that got to session!".to_string(),
            ));
        } else if incoming.message.header.session_id != *self.session_id.read().await? {
            return Err(Error::InvalidMessage(
                "Message not for this session!".to_string(),
            ));
        }

        Ok(incoming)
    }
}

#[cfg(feature = "sync")]
impl Drop for SessionMessageHandler {
    fn drop(&mut self) {
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

#[cfg(feature = "async")]
impl Drop for SessionMessageHandler {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.logoff_async().await;
            })
        })
    }
}
