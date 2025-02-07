use std::{collections::HashMap, error::Error, io::Cursor, sync::Arc};

use binrw::prelude::*;
use maybe_async::*;
#[cfg(not(feature = "async"))]
use std::sync::Mutex;
#[cfg(feature = "async")]
use tokio::sync::Mutex;

use crate::{
    compression::*,
    msg_handler::*,
    packets::{netbios::*, smb2::*},
    session::SessionState,
};

use super::negotiation_state::NegotiateState;

/// This struct is tranforming messages to plain, parsed SMB2,
/// including (en|de)cryption, (de)compression, and signing/verifying.
struct Transformer {
    sessions: Mutex<HashMap<u64, Arc<Mutex<SessionState>>>>,
}

impl Transformer {
    pub fn new(neg_state: &NegotiateState) -> Transformer {
        let compressor = match neg_state.compression {
            Some(compression) => Some(Compressor::new(
                compression.compression_algorithms.clone(),
                compression.flags.chained(),
            )),
            None => None,
        };
        let decompressor = Decompressor::new();

        Transformer {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Gets an OutgoingMessage ready for sending, performs crypto operations, and returns the
    /// final bytes to be sent.
    pub async fn tranform_outgoing(
        &mut self,
        mut msg: OutgoingMessage,
    ) -> Result<NetBiosTcpMessage, Box<dyn Error>> {
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
                    .ok_or("Session not found!")?
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
                if let Some(compressor) = &self.compressor {
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

    #[maybe_async]
    #[inline]
    pub async fn session_state(&self, session_id: u64) -> Option<Arc<Mutex<SessionState>>> {
        self.sessions.lock().await.get(&session_id).cloned()
    }

    /// Given a NetBiosTcpMessage, decrypts (if necessary), decompresses (if necessary) and returns the plain SMB2 message.
    pub async fn transform_incoming(
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
            let session = self
                .session_state(encrypted_message.header.session_id)
                .await
                .ok_or("Session not found")?;
            match session.lock().await.decryptor() {
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
            match &self.decompressor {
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
