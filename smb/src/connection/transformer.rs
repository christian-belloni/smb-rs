use crate::sync_helpers::*;
use crate::{
    compression::*,
    msg_handler::*,
    packets::{netbios::*, smb2::*},
    session::SessionInfo,
};
use binrw::prelude::*;
use maybe_async::*;
use std::{collections::HashMap, io::Cursor, sync::Arc};

use super::connection_info::ConnectionInfo;
use super::preauth_hash::{PreauthHashState, PreauthHashValue};

/// The [`Transformer`] structure is responsible for transforming messages to and from bytes,
/// send over NetBios TCP connection.
/// See [`Transformer::transform_outgoing`] and [`Transformer::transform_incoming`] for transformation functions.
#[derive(Debug)]
pub struct Transformer {
    /// Sessions opened from this connection.
    sessions: Mutex<HashMap<u64, Arc<Mutex<SessionInfo>>>>,

    config: RwLock<TransformerConfig>,

    preauth_hash: Mutex<Option<PreauthHashState>>,
}

#[derive(Default, Debug)]
struct TransformerConfig {
    /// Compressors for this connection.
    compress: Option<(Compressor, Decompressor)>,

    negotiated: bool,
}

impl Transformer {
    /// Notifies that the connection negotiation has been completed,
    /// with the given [`ConnectionInfo`].
    #[maybe_async]
    pub async fn negotiated(&self, neg_info: &ConnectionInfo) -> crate::Result<()> {
        {
            let config = self.config.read().await?;
            if config.negotiated {
                return Err(crate::Error::InvalidState(
                    "Connection is already negotiated!".into(),
                ));
            }
        }

        let mut config = self.config.write().await?;
        if neg_info.dialect.supports_compression() && neg_info.config.compression_enabled {
            let compress = match &neg_info.negotiation.compression {
                Some(compression) => {
                    Some((Compressor::new(compression), Decompressor::new(compression)))
                }
                None => None,
            };
            config.compress = compress;
        }

        config.negotiated = true;

        if !neg_info.dialect.preauth_hash_supported() {
            *self.preauth_hash.lock().await? = None;
        }

        Ok(())
    }

    /// Notifies that a session has started.
    #[maybe_async]
    pub async fn session_started(&self, session: Arc<Mutex<SessionInfo>>) -> crate::Result<()> {
        let rconfig = self.config.read().await?;
        if !rconfig.negotiated {
            return Err(crate::Error::InvalidState(
                "Connection is not negotiated yet!".to_string(),
            ));
        }

        let session_id = session.lock().await?.id();
        self.sessions
            .lock()
            .await?
            .insert(session_id, session.clone());

        Ok(())
    }

    /// Notifies that a session has ended.
    #[maybe_async]
    pub async fn session_ended(&self, session_id: u64) -> crate::Result<()> {
        let s = { self.sessions.lock().await?.remove(&session_id) };
        match s {
            Some(session_state) => {
                session_state.lock().await?.invalidate();
                Ok(())
            }
            None => Err(crate::Error::InvalidState("Session not found!".to_string())),
        }
    }

    /// Internal: Returns the session with the given ID.
    #[maybe_async]
    #[inline]
    async fn get_session(&self, session_id: u64) -> crate::Result<Arc<Mutex<SessionInfo>>> {
        self.sessions
            .lock()
            .await?
            .get(&session_id)
            .cloned()
            .ok_or(crate::Error::InvalidState(format!(
                "Session {} not found!",
                session_id
            )))
    }

    /// Internal: Calculates the next preauth integrity hash value, if required.
    #[maybe_async]
    async fn step_preauth_hash(&self, raw: &Vec<u8>) -> crate::Result<()> {
        let mut pa_hash = self.preauth_hash.lock().await?;
        // If already finished -- do nothing.
        if matches!(*pa_hash, Some(PreauthHashState::Finished(_))) {
            return Ok(());
        }
        // Do not touch if not set at all.
        if pa_hash.is_none() {
            return Ok(());
        }
        // Otherwise, update the hash!
        *pa_hash = pa_hash.take().unwrap().next(&raw).into();
        Ok(())
    }

    /// Finalizes the preauth hash. if it's not already finalized, and returns the value.
    /// If the hash is not supported, returns None.
    #[maybe_async]
    pub async fn finalize_preauth_hash(&self) -> crate::Result<Option<PreauthHashValue>> {
        let mut pa_hash = self.preauth_hash.lock().await?;
        if let Some(PreauthHashState::Finished(hash)) = &*pa_hash {
            return Ok(Some(hash.clone()));
        }

        *pa_hash = match pa_hash.take() {
            Some(pah) => pah.finish().into(),
            _ => return Ok(None),
        };

        match &*pa_hash {
            Some(PreauthHashState::Finished(hash)) => Ok(Some(hash.clone())),
            _ => panic!("Preauth hash not finished!"),
        }
    }

    /// Transforms an outgoing message to a [`NetBiosTcpMessage`].
    #[maybe_async]
    pub async fn transform_outgoing(
        &self,
        msg: OutgoingMessage,
    ) -> crate::Result<NetBiosTcpMessage> {
        let should_encrypt = msg.encrypt;
        let should_sign = msg.message.header.flags.signed();
        let set_session_id = msg.message.header.session_id;

        // 1. Sign
        let mut data = {
            let mut data = Vec::new();
            msg.message.write(&mut Cursor::new(&mut data))?;

            // 0. Update preauth hash as needed.
            self.step_preauth_hash(&data).await?;
            if should_sign {
                debug_assert!(
                    !should_encrypt,
                    "Should not sign and encrypt at the same time!"
                );
                let mut header_copy = msg.message.header.clone();

                let signer = {
                    self.get_session(set_session_id)
                        .await?
                        .lock()
                        .await?
                        .signer()
                        .cloned()
                };
                if let Some(mut signer) = signer {
                    signer.sign_message(&mut header_copy, &mut data)?;
                };
            };
            data
        };

        // 2. Compress
        data = {
            if msg.compress && data.len() > 1024 {
                let rconfig = self.config.read().await?;
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
                let session = self.get_session(set_session_id).await?;
                let encryptor = { session.lock().await?.encryptor().cloned() };
                if let Some(mut encryptor) = encryptor {
                    debug_assert!(should_encrypt && !should_sign);
                    let encrypted = encryptor.encrypt_message(data, set_session_id)?;
                    let mut cursor = Cursor::new(Vec::new());
                    Message::Encrypted(encrypted).write(&mut cursor)?;
                    cursor.into_inner()
                } else {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: true,
                        phase: TransformPhase::EncryptDecrypt,
                        session_id: Some(set_session_id),
                        why: "Message is required to be encrypted, but no encryptor is set up!",
                        msg_id: Some(msg.message.header.message_id),
                    }));
                }
            } else {
                data
            }
        };

        Ok(NetBiosTcpMessage::from_content_bytes(data))
    }

    /// Transforms an incoming [`NetBiosTcpMessage`] to an [`IncomingMessage`].
    #[maybe_async]
    pub async fn transform_incoming(
        &self,
        netbios: NetBiosTcpMessage,
    ) -> crate::Result<IncomingMessage> {
        let message = match netbios.parse_content()? {
            NetBiosMessageContent::SMB2Message(message) => Some(message),
            _ => None,
        }
        .ok_or(crate::Error::TranformFailed(TransformError {
            outgoing: false,
            phase: TransformPhase::EncodeDecode,
            session_id: None,
            why: "Message is not an SMB2 message!",
            msg_id: None,
        }))?;

        let mut form = MessageForm::default();

        // 3. Decrpt
        let (message, raw) = if let Message::Encrypted(encrypted_message) = &message {
            let session = self
                .get_session(encrypted_message.header.session_id)
                .await?;
            let decryptor = { session.lock().await?.decryptor().cloned() };
            form.encrypted = true;
            match decryptor {
                Some(mut decryptor) => decryptor.decrypt_message(&encrypted_message)?,
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::EncryptDecrypt,
                        session_id: Some(encrypted_message.header.session_id),
                        why: "Message is encrypted, but no decryptor is set up!",
                        msg_id: None,
                    }))
                }
            }
        } else {
            (message, netbios.content)
        };

        // 2. Decompress
        debug_assert!(!matches!(message, Message::Encrypted(_)));
        let (message, raw) = if let Message::Compressed(compressed_message) = &message {
            let rconfig = self.config.read().await?;
            form.compressed = true;
            match &rconfig.compress {
                Some(compress) => compress.1.decompress(compressed_message)?,
                None => {
                    return Err(crate::Error::TranformFailed(TransformError {
                        outgoing: false,
                        phase: TransformPhase::CompressDecompress,
                        session_id: None,
                        why: "Compression is requested, but no decompressor is set up!",
                        msg_id: None,
                    }))
                }
            }
        } else {
            (message, raw)
        };

        let mut message = match message {
            Message::Plain(message) => message,
            _ => panic!("Unexpected message type"),
        };

        // If fails, return TranformFailed, with message id.
        // this allows to notify the error to the task that was waiting for this message.
        match self
            .verify_plain_incoming(&mut message, &raw, &mut form)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                log::error!("Failed to verify incoming message: {:?}", e);
                return Err(crate::Error::TranformFailed(TransformError {
                    outgoing: false,
                    phase: TransformPhase::SignVerify,
                    session_id: Some(message.header.session_id),
                    why: "Failed to verify incoming message!",
                    msg_id: Some(message.header.message_id),
                }));
            }
        };

        self.step_preauth_hash(&raw).await?;

        Ok(IncomingMessage { message, raw, form })
    }

    /// Internal: a helper method to verify the incoming message.
    /// This method is used to verify the signature of the incoming message,
    /// if such verification is required.
    #[maybe_async]
    async fn verify_plain_incoming(
        &self,
        message: &mut PlainMessage,
        raw: &Vec<u8>,
        form: &mut MessageForm,
    ) -> crate::Result<()> {
        // Check if signing check is required.
        if form.encrypted
            || message.header.message_id == u64::MAX
            || message.header.status == Status::Pending as u32
            || !message.header.flags.signed()
        {
            return Ok(());
        }

        // Verify signature (if required, according to the spec)
        let session_id = message.header.session_id;
        let session = self.get_session(session_id).await?;
        let verifier = { session.lock().await?.signer().cloned() };
        if let Some(mut verifier) = verifier {
            form.signed = true;
            verifier.verify_signature(&mut message.header, raw)?;
            Ok(())
        } else {
            Err(crate::Error::TranformFailed(TransformError {
                outgoing: false,
                phase: TransformPhase::SignVerify,
                session_id: Some(session_id),
                why: "Message is signed, but no verifier is set up!",
                msg_id: Some(message.header.message_id),
            }))
        }
    }
}

impl Default for Transformer {
    fn default() -> Self {
        Self {
            sessions: Default::default(),
            config: Default::default(),
            // if not supported, will be set to None post-negotiation.
            preauth_hash: Mutex::new(Some(PreauthHashState::default())),
        }
    }
}

/// An error that can occur during the transformation of messages.
#[derive(Debug)]
pub struct TransformError {
    /// If true, the error occurred while transforming an outgoing message.
    /// If false, it occurred while transforming an incoming message.
    pub outgoing: bool,
    pub phase: TransformPhase,
    pub session_id: Option<u64>,
    pub why: &'static str,
    /// If a message ID is available, it will be set here,
    /// for error-handling purposes.
    pub msg_id: Option<u64>,
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

/// The phase of the transformation process.
#[derive(Debug)]
pub enum TransformPhase {
    /// Initial to/from bytes.
    EncodeDecode,
    /// Signature calculation and verification.
    SignVerify,
    /// Compression and decompression.
    CompressDecompress,
    /// Encryption and decryption.
    EncryptDecrypt,
}
