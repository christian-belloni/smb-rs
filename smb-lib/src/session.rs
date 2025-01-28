//! SMB Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use binrw::prelude::*;
use sspi::{AuthIdentity, Secret, Username};
use std::{cell::OnceCell, error::Error};

use crate::{
    authenticator::GssAuthenticator,
    client::ClientMessageHandler,
    crypto,
    msg_handler::{
        HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage, ReceiveOptions,
        SendMessageResult,
    },
    packets::smb2::{
        header::Status,
        negotiate::{EncryptionCipher, SigningAlgorithmId},
        plain::{Content, PlainMessage},
        session_setup::{SessionFlags, SessionSetupRequest},
    },
    tree::Tree,
};

type DerivedKeyValue = [u8; 16];
type UpstreamHandlerRef = HandlerReference<ClientMessageHandler>;

mod encryptor_decryptor;
mod signer;

pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};
pub use signer::MessageSigner;

pub struct Session {
    is_set_up: bool,
    handler: HandlerReference<SessionMessageHandler>,
}

impl Session {
    pub fn new(upstream: UpstreamHandlerRef) -> Session {
        Session {
            is_set_up: false,
            handler: SessionMessageHandler::new(upstream),
        }
    }

    pub fn setup(&mut self, user_name: String, password: String) -> Result<(), Box<dyn Error>> {
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
            GssAuthenticator::build(negotate_state.get_gss_token(), identity)?
        };

        let request = OutgoingMessage::new(PlainMessage::new(Content::SessionSetupRequest(
            SessionSetupRequest::new(next_buf),
        )));

        // response hash is processed later, in the loop.
        let response = self.handler.sendo_recvo(
            request,
            ReceiveOptions::new().status(Status::MoreProcessingRequired),
        )?;

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
                    let is_about_to_finish = authenticator.keys_exchanged() && !self.is_set_up;
                    request.finalize_preauth_hash = is_about_to_finish;
                    let result = self.handler.sendo(request)?;

                    // Keys exchanged? We can set-up the session!
                    if is_about_to_finish {
                        // Derive keys and set-up the final session.
                        let ntlm_key = authenticator.session_key()?.to_vec();
                        // Derive signing key, and set-up the session.
                        self.key_setup(&ntlm_key, result.preauth_hash.unwrap())?;
                    }

                    let expected_status = if is_about_to_finish {
                        Status::Success
                    } else {
                        Status::MoreProcessingRequired
                    };
                    let response = self
                        .handler
                        .recvo(ReceiveOptions::new().status(expected_status))?;
                    Some(response)
                }
                None => None,
            };
        }
        log::info!("Session setup complete.");
        self.handler.borrow_mut().session_flags = flags.unwrap();
        Ok(())
    }

    pub fn key_setup(
        &mut self,
        exchanged_session_key: &Vec<u8>,
        preauth_integrity_hash: [u8; 64],
    ) -> Result<(), Box<dyn Error>> {
        self.handler.borrow_mut().signing_key = Some(Self::derive_signing_key(
            exchanged_session_key,
            preauth_integrity_hash,
            b"SMBSigningKey\x00",
        )?);
        self.handler.borrow_mut().s2c_decryption_key = Some(Self::derive_signing_key(
            exchanged_session_key,
            preauth_integrity_hash,
            b"SMBS2CCipherKey\x00",
        )?);
        self.handler.borrow_mut().c2s_encryption_key = Some(Self::derive_signing_key(
            exchanged_session_key,
            preauth_integrity_hash,
            b"SMBC2SCipherKey\x00",
        )?);
        self.is_set_up = true;
        log::debug!("Session signing key set.");
        Ok(())
    }

    fn derive_signing_key(
        exchanged_session_key: &Vec<u8>,
        preauth_integrity_hash: [u8; 64],
        label: &[u8],
    ) -> Result<[u8; 16], Box<dyn Error>> {
        assert_eq!(exchanged_session_key.len(), 16);

        let mut session_key = [0; 16];
        session_key.copy_from_slice(&exchanged_session_key[0..16]);
        Ok(
            crypto::kbkdf_hmacsha256::<16>(&session_key, label, &preauth_integrity_hash)?
                .try_into()
                .unwrap(),
        )
    }

    pub fn signing_enabled(&self) -> bool {
        true
    }

    pub fn tree_connect(&mut self, name: String) -> Result<Tree, Box<dyn Error>> {
        let mut tree = Tree::new(name, self.handler.clone());
        tree.connect()?;
        Ok(tree)
    }

    fn logoff(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Logging off session.");

        let _response = self
            .handler
            .send_recv(Content::LogoffRequest(Default::default()))?;

        // Reset session ID and keys.
        self.handler.borrow_mut().session_id.take();
        self.handler.borrow_mut().signing_key.take();
        self.is_set_up = false;

        log::info!("Session logged off.");

        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.logoff().unwrap_or_else(|e| {
            log::error!("Failed to logoff: {}", e);
        });
    }
}

pub struct SessionMessageHandler {
    session_id: OnceCell<u64>,
    signing_key: Option<DerivedKeyValue>,
    s2c_decryption_key: Option<DerivedKeyValue>,
    c2s_encryption_key: Option<DerivedKeyValue>,
    signing_algo: SigningAlgorithmId,
    session_flags: SessionFlags,

    upstream: UpstreamHandlerRef,
}

impl SessionMessageHandler {
    pub fn new(upstream: UpstreamHandlerRef) -> HandlerReference<SessionMessageHandler> {
        let signing_algo = upstream
            .handler
            .borrow()
            .negotiate_state()
            .unwrap()
            .get_signing_algo();
        HandlerReference::new(SessionMessageHandler {
            session_id: OnceCell::new(),
            signing_key: None,
            s2c_decryption_key: None,
            c2s_encryption_key: None,
            session_flags: SessionFlags::new(),
            signing_algo,
            upstream,
        })
    }

    pub fn should_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    pub fn should_encrypt(&self) -> bool {
        debug_assert!(self.s2c_decryption_key.is_some() == self.c2s_encryption_key.is_some());
        self.s2c_decryption_key.is_some()
            && self.c2s_encryption_key.is_some()
            && self.session_flags.encrypt_data()
    }

    fn make_signer(&self) -> Result<MessageSigner, Box<dyn Error>> {
        if !self.should_sign() {
            return Err("Signing key is not set -- you must succeed a setup() to continue.".into());
        }

        debug_assert!(self.signing_key.is_some());

        Ok(MessageSigner::new(
            crypto::make_signing_algo(self.signing_algo, self.signing_key.as_ref().unwrap())
                .unwrap(),
        ))
    }

    fn make_encryptor(&self) -> Result<MessageEncryptor, Box<dyn Error>> {
        if !self.should_encrypt() {
            return Err(
                "Encrypting key is not set -- you must succeed a setup() to continue.".into(),
            );
        }

        debug_assert!(self.c2s_encryption_key.is_some());

        Ok(MessageEncryptor::new(
            crypto::make_encrypting_algo(
                EncryptionCipher::Aes128Ccm,
                self.c2s_encryption_key.as_ref().unwrap(),
            )
            .unwrap(),
        ))
    }

    fn make_decryptor(&self) -> Result<MessageDecryptor, Box<dyn Error>> {
        if !self.should_encrypt() {
            return Err(
                "Encrypting key is not set -- you must succeed a setup() to continue.".into(),
            );
        }

        debug_assert!(self.s2c_decryption_key.is_some());

        Ok(MessageDecryptor::new(
            crypto::make_encrypting_algo(
                EncryptionCipher::Aes128Ccm,
                self.s2c_decryption_key.as_ref().unwrap(),
            )
            .unwrap(),
        ))
    }
}

impl MessageHandler for SessionMessageHandler {
    fn hsendo(
        &mut self,
        mut msg: OutgoingMessage,
    ) -> Result<SendMessageResult, Box<(dyn std::error::Error + 'static)>> {
        // Set signing configuration. Upstream handler shall take care of the rest.
        if self.should_sign() {
            msg.message.header.flags.set_signed(true);
            msg.signer = Some(self.make_signer()?);
        }
        // Encryption
        if self.should_encrypt() {
            msg.encryptor = Some(self.make_encryptor()?);
        }
        msg.message.header.session_id = *self.session_id.get().or(Some(&0)).unwrap();
        self.upstream.borrow_mut().hsendo(msg)
    }

    fn hrecvo(
        &mut self,
        mut options: crate::msg_handler::ReceiveOptions,
    ) -> Result<IncomingMessage, Box<dyn std::error::Error>> {
        // Decryption
        if self.should_encrypt() {
            options.decryptor = Some(self.make_decryptor()?);
        }
        let mut incoming = self.upstream.borrow_mut().hrecvo(options)?;
        // TODO: check whether this is the correct case to do such a thing.
        if self.should_sign() && !incoming.form.encrypted {
            // Skip authentication is message ID is -1 or status is pending.
            if incoming.message.header.message_id != u64::MAX
                && incoming.message.header.status != Status::Pending
            {
                self.make_signer()?
                    .verify_signature(&mut incoming.message.header, &incoming.raw)?;
            }
        };
        Ok(incoming)
    }
}
