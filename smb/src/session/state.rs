//! Session state

use std::error::Error;
use std::sync::Arc;

use maybe_async::*;
#[cfg(not(feature = "async"))]
use std::sync::Mutex;
#[cfg(feature = "async")]
use tokio::sync::Mutex;

use crate::connection::negotiation_state::NegotiateState;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::crypto::{
    kbkdf_hmacsha256, make_encrypting_algo, make_signing_algo, DerivedKey, KeyToDerive,
};
use crate::packets::smb2::{EncryptionCipher, SessionFlags, SigningAlgorithmId};

use super::{MessageDecryptor, MessageEncryptor, MessageSigner};

/// Holds the state of a session, to be used for actions requiring data from session,
/// without accessing the entire session object.
/// This struct should be single-per-session, and wrapped in a shared pointer.
pub struct SessionState {
    session_id: u64,

    flags: SessionFlags,

    signer: Option<MessageSigner>,
    decryptor: Option<MessageDecryptor>,
    encryptor: Option<MessageEncryptor>,
}

impl SessionState {
    const SIGNING_KEY_LABEL: &[u8] = b"SMBSigningKey\x00";
    const S2C_DECRYPTION_KEY_LABEL: &[u8] = b"SMBS2CCipherKey\x00";
    const C2S_ENCRYPTION_KEY_LABEL: &[u8] = b"SMBC2SCipherKey\x00";

    #[maybe_async]
    pub async fn set(
        state: &mut Arc<Mutex<Self>>,
        session_key: &KeyToDerive,
        preauth_hash: &PreauthHashValue,
        negotation_state: &NegotiateState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deriver = KeyDeriver::new(session_key, preauth_hash);
        let signer = Self::make_signer(&deriver, negotation_state.signing_algo())?;
        let decryptor = Self::make_decryptor(&deriver, negotation_state.cipher())?;
        let encryptor = Self::make_encryptor(&deriver, negotation_state.cipher())?;

        let mut state = state.lock().await;
        state.signer = Some(signer);
        state.decryptor = Some(decryptor);
        state.encryptor = Some(encryptor);

        Ok(())
    }

    fn make_signer(
        deriver: &KeyDeriver,
        signing_algo: SigningAlgorithmId,
    ) -> Result<MessageSigner, Box<dyn Error>> {
        let signing_key = deriver.derive(Self::SIGNING_KEY_LABEL)?;
        Ok(MessageSigner::new(
            make_signing_algo(signing_algo, &signing_key).unwrap(),
        ))
    }

    fn make_encryptor(
        deriver: &KeyDeriver,
        cipher: EncryptionCipher,
    ) -> Result<MessageEncryptor, Box<dyn Error>> {
        let c2s_encryption_key = deriver.derive(Self::C2S_ENCRYPTION_KEY_LABEL)?;
        Ok(MessageEncryptor::new(
            make_encrypting_algo(cipher, &c2s_encryption_key).unwrap(),
        ))
    }

    fn make_decryptor(
        deriver: &KeyDeriver,
        cipher: EncryptionCipher,
    ) -> Result<MessageDecryptor, Box<dyn Error>> {
        let s2c_decryption_key = deriver.derive(Self::S2C_DECRYPTION_KEY_LABEL)?;

        Ok(MessageDecryptor::new(
            make_encrypting_algo(cipher, &s2c_decryption_key).unwrap(),
        ))
    }

    #[maybe_async]
    pub async fn set_flags(state: &mut Arc<Mutex<Self>>, flags: SessionFlags) {
        state.lock().await.flags = flags;
    }

    #[maybe_async]
    pub async fn invalidate(state: &mut Arc<Mutex<Self>>) {
        let mut state = state.lock().await;
        state.signer = None;
        state.decryptor = None;
        state.encryptor = None;
    }

    #[maybe_async]
    pub async fn signing_enabled(state: &Arc<Mutex<Self>>) -> bool {
        state.lock().await.signer.is_some()
    }

    #[maybe_async]
    pub async fn encryption_enabled(state: &Arc<Mutex<Self>>) -> bool {
        state.lock().await.encryptor.is_some() && state.lock().await.decryptor.is_some()
    }

    #[maybe_async]
    pub async fn is_set_up(state: &Arc<Mutex<Self>>) -> bool {
        Self::encryption_enabled(state).await || Self::signing_enabled(state).await
    }

    pub fn decryptor(&mut self) -> Option<&mut MessageDecryptor> {
        self.decryptor.as_mut()
    }

    pub fn encryptor(&mut self) -> Option<&mut MessageEncryptor> {
        self.encryptor.as_mut()
    }

    pub fn signer(&mut self) -> Option<&mut MessageSigner> {
        self.signer.as_mut()
    }
}

/// A helper struct for deriving SMB2 keys from a session key and preauth hash.
struct KeyDeriver<'a> {
    session_key: &'a KeyToDerive,
    preauth_hash: &'a PreauthHashValue,
}

impl<'a> KeyDeriver<'a> {
    #[inline]
    pub fn new(session_key: &'a KeyToDerive, preauth_hash: &'a PreauthHashValue) -> Self {
        Self {
            session_key,
            preauth_hash,
        }
    }

    #[inline]
    pub fn derive(&self, label: &[u8]) -> Result<DerivedKey, Box<dyn Error>> {
        kbkdf_hmacsha256::<16>(self.session_key, label, self.preauth_hash)
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_id: Default::default(),
            flags: SessionFlags::new(),
            signer: Default::default(),
            decryptor: Default::default(),
            encryptor: Default::default(),
        }
    }
}
