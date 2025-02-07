//! Session state

use std::sync::Arc;

use maybe_async::*;
#[cfg(not(feature = "async"))]
use std::sync::Mutex;
#[cfg(feature = "async")]
use tokio::sync::Mutex;

use crate::packets::smb2::{SessionFlags, SigningAlgorithmId};
use crate::crypto::{DerivedKey, KeyToDerive, kbkdf}

use super::{MessageDecryptor, MessageSigner};

/// Holds the state of a session, to be used for actions requiring data from session,
/// without accessing the entire session object.
/// This struct should be single-per-session, and wrapped in a shared pointer.
pub struct SessionState {
    session_id: u64,

    flags: SessionFlags,

    signer: Option<Arc<Mutex<MessageSigner>>>,
    decryptor: Option<Arc<Mutex<MessageDecryptor>>>,
}

impl SessionState {
    // #[maybe_async]
    async fn set(
        state: &mut Arc<Mutex<Self>>,
        session_key: KeyToDerive
    ) {
        let mut state = state.lock().await;
        state.signer = signer;
        state.decryptor = decryptor;
    }

    fn make_signer(&self, signing_key: DerivedKey) -> Result<MessageSigner, Box<dyn Error>> {
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

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_id: Default::default(),
            flags: SessionFlags::new(),
            signer: Default::default(),
            decryptor: Default::default(),
        }
    }
}
