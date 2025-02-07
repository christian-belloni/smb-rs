//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::{
    connection::{connection::ClientMessageHandler, preauth_hash::PreauthHashValue},
    crypto::{self, KeyToDerive},
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
        SendMessageResult,
    },
    packets::smb2::*,
    tree::Tree,
};
use binrw::prelude::*;
use maybe_async::*;
use sspi::{AuthIdentity, Secret, Username};
use std::{cell::OnceCell, error::Error, sync::Arc};
use tokio::sync::Mutex;

type UpstreamHandlerRef = HandlerReference<ClientMessageHandler>;

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
    session_state: Arc<Mutex<SessionState>>,
}

impl Session {
    pub fn new(upstream: UpstreamHandlerRef) -> Session {
        let session_state = Arc::new(Mutex::new(SessionState::default()));
        Session {
            handler: SessionMessageHandler::new(upstream, session_state.clone()),
            session_state: session_state,
        }
    }

    #[maybe_async]
    pub async fn setup(
        &mut self,
        user_name: String,
        password: String,
    ) -> Result<(), Box<dyn Error>> {
        log::debug!("Setting up session for user {}.", user_name);
        // Build the authenticator.
        let (mut authenticator, next_buf) = {
            let handler = self.handler.borrow();
            let handler = handler.upstream.borrow();
            let negotate_state = handler.negotiate_state().unwrap();
            let identity = AuthIdentity {
                username: Username::new(&user_name, Some("WORKGROUP"))?,
                password: Secret::new(password),
            };
            GssAuthenticator::build(negotate_state.gss_token(), identity)?
        };

        let request = OutgoingMessage::new(PlainMessage::new(Content::SessionSetupRequest(
            SessionSetupRequest::new(next_buf),
        )));

        // response hash is processed later, in the loop.
        let response = self
            .handler
            .sendo_recvo(
                request,
                ReceiveOptions::new().status(Status::MoreProcessingRequired),
            )
            .await?;

        // Set session id.
        self.handler
            .borrow_mut()
            .session_id
            .set(response.message.header.session_id)
            .map_err(|_| "Session ID already set!")?;

        let mut response = Some(response);
        let mut flags = None;
        while !authenticator.is_authenticated()? {
            // If there's a response to process, do so.
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
                    let mut request = OutgoingMessage::new(PlainMessage::new(
                        Content::SessionSetupRequest(SessionSetupRequest::new(next_buf)),
                    ));
                    let is_about_to_finish = authenticator.keys_exchanged()
                        && !SessionState::is_set_up(&self.session_state).await;
                    request.finalize_preauth_hash = is_about_to_finish;
                    let result = self.handler.sendo(request).await?;

                    // If keys are exchanged, set them up, to enable validation of next response!
                    if is_about_to_finish {
                        let ntlm_key: KeyToDerive = authenticator.session_key()?;
                        self.key_setup(&ntlm_key, &result.preauth_hash.unwrap())
                            .await?;
                    }

                    let expected_status = if is_about_to_finish {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };
                    let response = self
                        .handler
                        .recvo(ReceiveOptions::new().status(expected_status))
                        .await?;
                    Some(response)
                }
                None => None,
            };
        }
        log::info!("Session setup complete.");

        SessionState::set_flags(&mut self.session_state, flags.unwrap()).await;
        Ok(())
    }

    // #[maybe_async]
    pub async fn key_setup(
        &mut self,
        exchanged_session_key: &KeyToDerive,
        preauth_hash: &PreauthHashValue,
    ) -> Result<(), Box<dyn Error>> {
        let s = self.handler.borrow();
        let s = s.upstream.borrow();
        let state = s.negotiate_state().unwrap();

        SessionState::set(
            &mut self.session_state,
            exchanged_session_key,
            preauth_hash,
            state,
        )
        .await?;

        log::debug!("Session signing key set.");
        Ok(())
    }

    pub fn signing_enabled(&self) -> bool {
        true
    }

    #[maybe_async]
    pub async fn tree_connect(&mut self, name: String) -> Result<Tree, Box<dyn Error>> {
        let mut tree = Tree::new(name, self.handler.clone());
        tree.connect().await?;
        Ok(tree)
    }

    #[maybe_async]
    async fn logoff(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Logging off session.");

        let _response = self
            .handler
            .send_recv(Content::LogoffRequest(Default::default()))
            .await?;

        // Reset session ID and keys.
        self.handler.borrow_mut().session_id.take();
        SessionState::invalidate(&mut self.session_state).await;

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

#[cfg(not(feature = "async"))]
impl Drop for Session {
    fn drop(&mut self) {
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

#[cfg(feature = "async")]
impl Drop for Session {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.logoff_async().await;
            })
        })
    }
}

pub struct SessionMessageHandler {
    session_id: OnceCell<u64>,
    upstream: UpstreamHandlerRef,

    session_state: Arc<Mutex<SessionState>>,
}

impl SessionMessageHandler {
    pub fn new(
        upstream: UpstreamHandlerRef,
        session_state: Arc<Mutex<SessionState>>,
    ) -> HandlerReference<SessionMessageHandler> {
        HandlerReference::new(SessionMessageHandler {
            session_id: OnceCell::new(),
            upstream,
            session_state,
        })
    }

    #[maybe_async]
    pub async fn should_sign(&self) -> bool {
        SessionState::signing_enabled(&self.session_state).await
    }

    #[maybe_async]
    pub async fn should_encrypt(&self) -> bool {
        SessionState::encryption_enabled(&self.session_state).await
    }

    fn upstream(&self) -> &UpstreamHandlerRef {
        &self.upstream
    }
}

impl MessageHandler for SessionMessageHandler {
    #[maybe_async]
    async fn hsendo(
        &mut self,
        mut msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<(dyn std::error::Error + 'static)>> {
        // Encrypt?
        if self.should_encrypt().await {
            msg.encrypt = true;
        }
        // Sign instead?
        else if self.should_sign().await {
            msg.message.header.flags.set_signed(true);
        }
        msg.message.header.session_id = *self.session_id.get().or(Some(&0)).unwrap();
        self.upstream.borrow_mut().hsendo(msg).await
    }

    // #[maybe_async]
    async fn hrecvo(
        &mut self,
        mut options: crate::msg_handler::ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        let incoming = self.upstream.borrow_mut().hrecvo(options).await?;
        // Make sure that it's our session.
        if incoming.message.header.session_id != 0 {
            if incoming.message.header.session_id != *self.session_id.get().unwrap() {
                return Err("Received message for different session.".into());
            }
        }
        Ok(incoming)
    }
}
