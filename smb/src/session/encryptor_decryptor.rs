//! SMB Message encryption/decryption implementation.

use binrw::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::Cursor;

use crate::{
    crypto,
    packets::smb2::{encrypted::*, message::Message}, Error,
};

#[derive(Debug)]
pub struct MessageEncryptor {
    algo: Box<dyn crypto::EncryptingAlgo>,
}

impl MessageEncryptor {
    pub fn new(algo: Box<dyn crypto::EncryptingAlgo>) -> MessageEncryptor {
        MessageEncryptor { algo }
    }

    /// Encrypts message in-place.
    pub fn encrypt_message(
        &mut self,
        mut message: Vec<u8>,
        session_id: u64,
    ) -> Result<EncryptedMessage, Error> {
        debug_assert!(session_id != 0);

        // Serialize message:
        let mut header = EncryptedHeader {
            signature: 0,
            nonce: self.gen_nonce(),
            original_message_size: message.len().try_into()?,
            session_id: session_id,
        };

        let result = self
            .algo
            .encrypt(&mut message, &header.aead_bytes(), &header.nonce)?;

        header.signature = result.signature;

        log::debug!("Encrypted message with signature: {:?}", header.signature);

        Ok(EncryptedMessage {
            header,
            encrypted_message: message,
        })
    }

    fn gen_nonce(&self) -> [u8; 16] {
        let mut nonce = [0; 16];
        // Generate self.algo.nonce_size() random bytes:
        OsRng.fill_bytes(&mut nonce[..self.algo.nonce_size()]);
        nonce
    }
}

#[derive(Debug)]
pub struct MessageDecryptor {
    algo: Box<dyn crypto::EncryptingAlgo>,
}

impl MessageDecryptor {
    pub fn new(algo: Box<dyn crypto::EncryptingAlgo>) -> MessageDecryptor {
        MessageDecryptor { algo }
    }

    pub fn decrypt_message(
        &mut self,
        msg_in: &EncryptedMessage,
    ) -> Result<(Message, Vec<u8>), Error> {
        let mut serialized_message = msg_in.encrypted_message.clone();
        self.algo.decrypt(
            &mut serialized_message,
            &msg_in.header.aead_bytes(),
            &msg_in.header.nonce,
            msg_in.header.signature,
        )?;

        let result = Message::read(&mut Cursor::new(&serialized_message))?;

        log::debug!("Decrypted with signature {}", msg_in.header.signature);
        Ok((result, serialized_message))
    }
}
