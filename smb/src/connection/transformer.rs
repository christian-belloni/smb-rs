use super::Error;
use binrw::prelude::*;
use maybe_async::*;
#[cfg(not(feature = "async"))]
use std::sync::Mutex;
use std::{collections::HashMap, io::Cursor, sync::Arc};
#[cfg(feature = "async")]
use tokio::sync::{Mutex, RwLock};

use crate::{
    compression::*,
    msg_handler::*,
    packets::{netbios::*, smb2::*},
    session::SessionState,
};

use super::negotiation_state::NegotiateState;

/// This struct is tranforming messages to plain, parsed SMB2,
/// including (en|de)cryption, (de)compression, and signing/verifying.
#[derive(Default, Debug)]
pub struct Transformer {
    /// Sessions opened from this connection.
    sessions: Mutex<HashMap<u64, Arc<Mutex<SessionState>>>>,

    config: RwLock<TranformerConfig>,
}

#[derive(Default, Debug)]
struct TranformerConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,
}

impl Transformer {
    /// When the connection is negotiated, this function is called to set up additional transformers,
    /// according to the allowed in the negotiation state.
    #[maybe_async]
    pub async fn negotiated(&self, neg_state: &NegotiateState) -> Result<(), crate::Error> {
        {
            let config = self.config.read().await;
            if config.negotiated {
                return Err(crate::Error::InvalidStateError(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await;

        let compress = match &neg_state.compression {
            Some(compression) => {
                Some((Compressor::new(compression), Decompressor::new(compression)))
            }
            None => None,
        };
        config.compress = compress;
        config.negotiated = true;

        Ok(())
    }

    /// Adds the session to the list of active sessions.
    #[maybe_async]
    pub async fn session_started(
        &self,
        session: Arc<Mutex<SessionState>>,
    ) -> Result<(), crate::Error> {
        let rconfig = self.config.read().await;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidStateError(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = session.lock().await.session_id;
        self.sessions
            .lock()
            .await
            .insert(session_id, session.clone());

        Ok(())
    }

    #[maybe_async]
    pub async fn session_ended(&self, session_id: u64) {
        self.sessions.lock().await.remove(&session_id);
    }

    #[maybe_async]
    #[inline]
    pub async fn session_state(&self, session_id: u64) -> Option<Arc<Mutex<SessionState>>> {
        self.sessions.lock().await.get(&session_id).cloned()
    }

    /// Gets an OutgoingMessage ready for sending, performs crypto operations, and returns the
    /// final bytes to be sent.
    #[maybe_async]
    pub async fn tranform_outgoing(
        &self,
        mut msg: OutgoingMessage,
    ) -> Result<NetBiosTcpMessage, crate::Error> {
        let should_encrypt = msg.encrypt;
        let should_sign = msg.message.header.flags.signed();
        let set_session_id = msg.message.header.session_id;

        // 1. Sign
        let mut data = {
            let mut data = Vec::new();
            msg.message.write(&mut Cursor::new(&mut data))?;

            // 0. Update preauth hash as needed.
            self.step_preauth_hash(&data);
            if should_sign {
                debug_assert!(
                    !should_encrypt,
                    "Should not sign and encrypt at the same time!"
                );
                let mut header_copy = msg.message.header.clone();
                if let Some(mut signer) = self
                    .session_state(set_session_id)
                    .await
                    .ok_or(crate::Error::TranformFailedError(TransformError {
                        outgoing: true,
                        phase: TranformPhase::SignVerify,
                        session_id: Some(set_session_id),
                        why: "Session not found for message!",
                    }))?
                    .lock()
                    .await
                    .signer()
                {
                    signer.sign_message(&mut header_copy, &mut data)?;
                };
            };
            data
        };

        // 2. Compress
        data = {
            if msg.compress && data.len() > 1024 {
                let rconfig = self.config.read().await;
                if let Some(compress) = &rconfig.compress {
                    let compressed = compress.0.compress(&data)?;
                    data.clear();
                    let mut cursor = Cursor::new(&mut data);
                    Message::Compressed(compressed).write(&mut cursor)?;
                };
            }
            data
        };

        // 3. Encrypt
        let data = {
            if msg.encrypt {
                let session = self.session_state(set_session_id).await.ok_or(
                    crate::Error::InvalidStateError("Session not found!".to_string()),
                )?;
                if let Some(mut encryptor) = session.lock().await.encryptor() {
                    debug_assert!(should_encrypt && !should_sign);
                    let encrypted = encryptor.encrypt_message(data, set_session_id)?;
                    let mut cursor = Cursor::new(Vec::new());
                    Message::Encrypted(encrypted).write(&mut cursor)?;
                    cursor.into_inner()
                } else {
                    return Err(crate::Error::TranformFailedError(
                        TransformError {
                            outgoing: true,
                            phase: TranformPhase::EncryptDecrypt,
                            session_id: Some(set_session_id),
                            why: "Message is encrypted, but no encryptor is set up!",
                        },
                    ));
                }
            } else {
                data
            }
        };

        Ok(NetBiosTcpMessage::from_content_bytes(data))
    }

    /// Given a NetBiosTcpMessage, decrypts (if necessary), decompresses (if necessary) and returns the plain SMB2 message.
    pub async fn transform_incoming(
        &self,
        netbios: NetBiosTcpMessage,
    ) -> Result<IncomingMessage, crate::Error> {
        let message = match netbios.parse_content()? {
            NetBiosMessageContent::SMB2Message(message) => Some(message),
            _ => None,
        }
        .ok_or(crate::Error::TranformFailedError(TransformError {
            outgoing: false,
            phase: TranformPhase::EncodeDecode,
            session_id: None,
            why: "Message is not an SMB2 message!",
        }))?;

        let mut form = MessageForm::default();

        // 1. Decrpt
        let (message, raw) = if let Message::Encrypted(encrypted_message) = &message {
            form.encrypted = true;
            let session = self
                .session_state(encrypted_message.header.session_id)
                .await
                .ok_or(crate::Error::TranformFailedError(TransformError {
                    outgoing: false,
                    phase: TranformPhase::EncryptDecrypt,
                    session_id: Some(encrypted_message.header.session_id),
                    why: "Session not found for message!",
                }))?;
            let mut session = session.lock().await;
            match session.decryptor() {
                Some(decryptor) => decryptor.decrypt_message(&encrypted_message)?,
                None => {
                    return Err(crate::Error::TranformFailedError(TransformError {
                        outgoing: false,
                        phase: TranformPhase::EncryptDecrypt,
                        session_id: Some(encrypted_message.header.session_id),
                        why: "Message is encrypted, but no decryptor is set up!",
                    }))
                }
            }
        } else {
            (message, netbios.content)
        };

        // 2. Decompress
        debug_assert!(!matches!(message, Message::Encrypted(_)));
        let (message, raw) = if let Message::Compressed(compressed_message) = &message {
            form.compressed = true;
            let rconfig = self.config.read().await;
            match &rconfig.compress {
                Some(compress) => compress.1.decompress(compressed_message)?,
                None => {
                    return Err(crate::Error::TranformFailedError(TransformError {
                        outgoing: false,
                        phase: TranformPhase::CompressDecompress,
                        session_id: None,
                        why: "Compression is requested, but no decompressor is set up!",
                    }))
                }
            }
        } else {
            (message, raw)
        };

        // unwrap Message::Plain from Message enum:
        let message = match message {
            Message::Plain(message) => message,
            _ => panic!("Unexpected message type"),
        };

        Ok(IncomingMessage { message, raw, form })
    }
}

#[derive(Debug)]
pub struct TransformError {
    outgoing: bool,
    phase: TranformPhase,
    session_id: Option<u64>,
    why: &'static str,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.outgoing {
            write!(
                f,
                "Failed to transform outgoing message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        } else {
            write!(
                f,
                "Failed to transform incoming message: {:?} (session_id: {:?}) - {}",
                self.phase, self.session_id, self.why
            )
        }
    }
}

#[derive(Debug)]
pub enum TranformPhase {
    EncodeDecode,
    SignVerify,
    CompressDecompress,
    EncryptDecrypt,
}
