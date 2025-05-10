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

use authenticator::{AuthenticationStep, Authenticator};
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;
pub use state::SessionInfo;

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

        log::debug!("Setting up session for user {}.", user_name);

        let username = Username::parse(user_name).map_err(|e| Error::SspiError(e.into()))?;
        let identity = AuthIdentity {
            username,
            password: Secret::new(password),
        };
        // Build the authenticator.
        let mut authenticator = Authenticator::build(identity, conn_info)?;
        let next_buf = match authenticator.next(&conn_info.negotiation.auth_buffer)? {
            AuthenticationStep::NextToken(buf) => buf,
            AuthenticationStep::Complete => {
                return Err(Error::InvalidState(
                    "Authentication completed before session setup.".to_string(),
                ))
            }
        };
        let request = OutgoingMessage::new(Content::SessionSetupRequest(SessionSetupRequest::new(
            next_buf,
            req_security_mode,
        )));

        // response hash is processed later, in the loop.
        let init_response = upstream
            .sendo_recvo(
                request,
                ReceiveOptions::new()
                    .with_status(&[Status::MoreProcessingRequired, Status::Success]),
            )
            .await?;

        let session_id = init_response.message.header.session_id;
        // Construct info object and handler.
        let session_state = Arc::new(Mutex::new(SessionInfo::new(session_id)));
        let handler = SessionMessageHandler::new(session_id, upstream, session_state.clone());

        let setup_result = if init_response.message.header.status == Status::Success as u32 {
            unimplemented!()
        } else {
            Self::setup_more_processing(
                &mut authenticator,
                init_response.message.content.to_sessionsetupresponse()?,
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
                // Notify the worker that the session is invalid.
                if let Err(x) = upstream
                    .worker()
                    .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
                    .session_ended(handler.session_id)
                    .await
                {
                    log::debug!("Failed to notify worker about session end: {}!", x);
                }
                return Err(e);
            }
        };

        log::info!("Session setup complete.");
        if flags.is_guest_or_null_session() {
            log::info!("Session is guest/anonymous.");
        }

        session_state.lock().await?.set_flags(flags, &conn_info)?;

        let session = Session {
            handler,
            conn_info: conn_info.clone(),
        };

        Ok(session)
    }

    #[maybe_async]
    pub async fn setup_more_processing(
        authenticator: &mut Authenticator,
        init_response: SessionSetupResponse,
        session_state: &Arc<Mutex<SessionInfo>>,
        req_security_mode: SessionSecurityMode,
        handler: &HandlerReference<SessionMessageHandler>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<SessionFlags> {
        let mut last_setup_response = Some(init_response);
        let mut flags = None;

        // While there's a response to process, do so.
        while !authenticator.is_authenticated()? {
            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer)?,
                None => authenticator.next(&vec![])?,
            };
            let is_auth_done = authenticator.is_authenticated()?;

            last_setup_response = match next_buf {
                AuthenticationStep::NextToken(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let mut request = OutgoingMessage::new(Content::SessionSetupRequest(
                        SessionSetupRequest::new(next_buf, req_security_mode),
                    ));
                    request.finalize_preauth_hash = is_auth_done;
                    let result = handler.sendo(request).await?;

                    // If keys are exchanged, set them up, to enable validation of next response!

                    if is_auth_done {
                        let session_key: KeyToDerive = authenticator.session_key()?;

                        session_state.lock().await?.setup(
                            &session_key,
                            &result.preauth_hash,
                            conn_info,
                        )?;
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

                    let expected_status = if is_auth_done {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };
                    let response = handler
                        .recvo_internal(
                            ReceiveOptions::new()
                                .with_status(&[expected_status])
                                .with_msg_id_filter(result.msg_id),
                            is_auth_done,
                        )
                        .await?;

                    let message_form = response.form;
                    let session_setup_response =
                        response.message.content.to_sessionsetupresponse()?;

                    if is_auth_done {
                        // Important: If we did NOT make sure the message's signature is valid,
                        // we should do it now, as long as the session is not anonymous or guest.
                        if !session_setup_response
                            .session_flags
                            .is_guest_or_null_session()
                            && !message_form.signed_or_encrypted()
                        {
                            return Err(Error::InvalidMessage(
                                "Expected a signed message!".to_string(),
                            ));
                        }
                    }

                    flags = Some(session_setup_response.session_flags);
                    Some(session_setup_response)
                }
                AuthenticationStep::Complete => None,
            };
        }

        flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))
    }

    /// *Internal:* Connects to the specified tree using the current session.
    #[maybe_async]
    async fn do_tree_connect(&self, name: &str, dfs: bool) -> crate::Result<Tree> {
        Tree::connect(name, &self.handler, &self.conn_info, dfs).await
    }

    /// Connects to the specified tree using the current session.
    /// # Arguments
    /// * `name` - The name of the tree to connect to. This should be a UNC path, with only server and share,
    ///     for example, `\\server\share`.
    /// # Notes
    /// See [`Session::dfs_tree_connect`] for connecting to a share as a DFS referral.
    #[maybe_async]
    pub async fn tree_connect(&self, name: &str) -> crate::Result<Tree> {
        self.do_tree_connect(name, false).await
    }

    /// Connects to the specified tree using the current session as a DFS referral.
    ///
    #[maybe_async]
    pub async fn dfs_tree_connect(&self, name: &str) -> crate::Result<Tree> {
        self.do_tree_connect(name, true).await
    }
}

pub struct SessionMessageHandler {
    session_id: u64,
    upstream: Upstream,

    session_state: Arc<Mutex<SessionInfo>>,
}

impl SessionMessageHandler {
    pub fn new(
        session_id: u64,
        upstream: &Upstream,
        session_state: Arc<Mutex<SessionInfo>>,
    ) -> HandlerReference<SessionMessageHandler> {
        HandlerReference::new(SessionMessageHandler {
            session_id,
            upstream: upstream.clone(),
            session_state,
        })
    }

    #[maybe_async]
    async fn logoff(&self) -> crate::Result<()> {
        {
            let state = self.session_state.lock().await?;
            if !state.is_set_up() {
                log::trace!("Session not set up/already logged-off.");
                return Ok(());
            }
        }

        log::debug!("Logging off session.");

        let _response = self
            .send_recv(Content::LogoffRequest(Default::default()))
            .await?;

        // This also invalidates the session object.
        self.upstream
            .handler
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(self.session_id)
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

    /// **UNSECURE METHOD: Only use within the session setup process.**
    ///
    /// INTERNAL: Sends a message and receives a response.
    #[maybe_async]
    async fn recvo_internal(
        &self,
        options: ReceiveOptions<'_>,
        skip_security_checks: bool,
    ) -> crate::Result<IncomingMessage> {
        // allow unsigned messages only if the session is anonymous or guest.
        // this is enforced against configuration when setting up the session.
        let unsigned_allowed = {
            let session = self.session_state.lock().await?;
            if session.is_invalid() {
                return Err(Error::InvalidState("Session is invalid".to_string()).into());
            }
            session.is_guest_or_anonymous() || skip_security_checks
        };

        let incoming = self.upstream.recvo(options).await?;
        // Make sure that it's our session.
        if incoming.message.header.session_id == 0 {
            return Err(Error::InvalidMessage(
                "No session ID in message that got to session!".to_string(),
            ));
        } else if incoming.message.header.session_id != self.session_id {
            return Err(Error::InvalidMessage(
                "Message not for this session!".to_string(),
            ));
        // And that it's an authenticated message.
        } else if !incoming.form.signed_or_encrypted() && !unsigned_allowed {
            return Err(Error::InvalidMessage(
                "Message not signed or encrypted, but signing is required for the session!"
                    .to_string(),
            ));
        }

        Ok(incoming)
    }
}

impl MessageHandler for SessionMessageHandler {
    #[maybe_async]
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        {
            let session = self.session_state.lock().await?;
            if session.is_invalid() {
                return Err(Error::InvalidState("Session is invalid".to_string()).into());
            }

            if session.is_set_up() {
                // Encrypt?
                if session.should_encrypt() {
                    msg.encrypt = true;
                }
                // Sign instead?
                else if !session.is_guest_or_anonymous() {
                    msg.message.header.flags.set_signed(true);
                }
                // TODO: Re-check against config whether it's allowed to send/receive unsigned messages?
            }
        }
        msg.message.header.session_id = self.session_id;
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        self.recvo_internal(options, false).await
    }
}

#[cfg(not(feature = "async"))]
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
