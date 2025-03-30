//! Session information and state

use std::sync::Arc;

use crate::dialects::DialectImpl;
use crate::sync_helpers::*;

use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::crypto::{
    kbkdf_hmacsha256, make_encrypting_algo, make_signing_algo, CryptoError, DerivedKey, KeyToDerive,
};
use crate::packets::smb2::{Dialect, EncryptionCipher, SessionFlags, SigningAlgorithmId};

use super::{MessageDecryptor, MessageEncryptor, MessageSigner};

/// Holds the information of a session, to be used for actions requiring data from session,
/// without accessing the entire session object.
/// This struct should be single-per-session, and wrapped in a shared pointer.
#[derive(Debug)]
pub struct SessionInfo {
    session_id: u64,
    flags: OnceCell<SessionFlags>,
    state: Option<SessionInfoState>,
}

/// Holds the algorithms used for the session --
/// signing, encryption, and decryption algorithms.
#[derive(Debug)]
struct SessionAlgos {
    signer: MessageSigner,
    encryptor: Option<MessageEncryptor>,
    decryptor: Option<MessageDecryptor>,
}

#[derive(Debug, Default)]
enum SessionInfoState {
    #[default]
    /// The session is not set up yet.
    Initialized,
    /// The session is set up, but not yet authenticated.
    SetUp { algos: SessionAlgos },
    /// The session is invalid, and should not be used anymore.
    Invalid,
}

impl SessionInfo {
    pub const NO_PREAUTH_HASH_DERIVE_SIGN_CTX: &[u8] = b"SmbSign\x00";
    pub const NO_PREAUTH_HASH_DERIVE_ECRNYPT_S2C_CTX: &[u8] = b"ServerOut\x00";
    pub const NO_PREAUTH_HASH_DERIVE_ENCRYPT_C2S_CTX: &[u8] = b"ServerIn \x00";

    /// Creates a new session info object.
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            state: Some(SessionInfoState::Initialized),
            flags: Default::default(),
        }
    }

    pub fn id(&self) -> u64 {
        self.session_id
    }

    /// Sets up the session state with the given session key and preauth hash.

    pub fn setup(
        &mut self,
        session_key: &KeyToDerive,
        preauth_hash: &Option<PreauthHashValue>,
        info: &ConnectionInfo,
    ) -> crate::Result<()> {
        if !matches!(self.state, Some(SessionInfoState::Initialized)) {
            return Err(crate::Error::InvalidState(
                "Session is not in state initialized, cannot set up.".to_string(),
            ));
        }

        if (info.negotiation.dialect_rev == Dialect::Smb0311) != preauth_hash.is_some() {
            return Err(crate::Error::InvalidMessage(
                "Preauth hash must be present for SMB3.1.1, and not present for SMB3.0.2 or older revisions."
                    .to_string(),
            ));
        }

        let algos = if info.negotiation.dialect_rev.is_smb3() {
            Self::smb3xx_make_ciphers(session_key, preauth_hash, info)?
        } else {
            SessionAlgos {
                signer: Self::smb2_make_signer(session_key, info)?.into(),
                encryptor: None,
                decryptor: None,
            }
        };

        log::trace!("Session algos set up: {:?}", algos);
        self.state = Some(SessionInfoState::SetUp { algos });

        Ok(())
    }

    fn smb2_make_signer(
        session_key: &KeyToDerive,
        info: &ConnectionInfo,
    ) -> Result<MessageSigner, CryptoError> {
        debug_assert!(info.negotiation.dialect_rev < Dialect::Smb030);
        Ok(MessageSigner::new(make_signing_algo(
            SigningAlgorithmId::HmacSha256,
            session_key,
        )?))
    }

    fn smb3xx_make_ciphers(
        session_key: &KeyToDerive,
        preauth_hash: &Option<PreauthHashValue>,
        info: &ConnectionInfo,
    ) -> crate::Result<SessionAlgos> {
        let deriver = KeyDeriver::new(session_key);

        let signer = Self::smb3xx_make_signer(
            &deriver,
            info.negotiation.signing_algo,
            &info.dialect,
            preauth_hash,
        )?;

        let (enc, dec) = if let Some((e, d)) =
            Self::smb3xx_make_cipher_pair(&deriver, info, preauth_hash)?
        {
            (Some(e), Some(d))
        } else {
            if info.config.encryption_mode.is_required() {
                return Err(crate::Error::InvalidMessage(
                    "Encryption is required, seems to be unsupported by the server with current config.".to_string(),
                ));
            };
            (None, None)
        };

        Ok(SessionAlgos {
            signer,
            encryptor: enc,
            decryptor: dec,
        })
    }

    fn smb3xx_make_signer(
        deriver: &KeyDeriver,
        signing_algo: Option<SigningAlgorithmId>,
        dialect: &Arc<DialectImpl>,
        preauth_hash: &Option<PreauthHashValue>,
    ) -> Result<MessageSigner, CryptoError> {
        let signing_key = deriver.derive(
            dialect.get_signing_derive_label(),
            Self::preauth_hash_or(preauth_hash, Self::NO_PREAUTH_HASH_DERIVE_SIGN_CTX),
        )?;
        let signing_algo = match signing_algo {
            Some(a) => a,
            None => dialect.default_signing_algo(),
        };
        Ok(MessageSigner::new(make_signing_algo(
            signing_algo,
            &signing_key,
        )?))
    }

    fn smb3xx_make_cipher_pair(
        deriver: &KeyDeriver,
        info: &ConnectionInfo,
        preauth_hash: &Option<PreauthHashValue>,
    ) -> Result<Option<(MessageEncryptor, MessageDecryptor)>, CryptoError> {
        // Not supported
        if !info.dialect.supports_encryption() {
            return Ok(None);
        }
        // Disabled in config
        if info.config.encryption_mode.is_disabled() {
            return Ok(None);
        }
        // Cipher is selected only for SMB3.1.1
        debug_assert_eq!(
            (info.negotiation.dialect_rev == Dialect::Smb0311),
            info.negotiation.encryption_cipher.is_some()
        );
        // Use AES-128-CCM by default.
        let cipher = match info.negotiation.encryption_cipher {
            Some(c) => c,
            None => EncryptionCipher::Aes128Ccm,
        };

        // Make the keys.
        let enc_key = deriver.derive(
            info.dialect.c2s_encrypt_key_derive_label(),
            Self::preauth_hash_or(preauth_hash, Self::NO_PREAUTH_HASH_DERIVE_ENCRYPT_C2S_CTX),
        )?;
        let dec_key = deriver.derive(
            info.dialect.s2c_encrypt_key_derive_label(),
            Self::preauth_hash_or(preauth_hash, Self::NO_PREAUTH_HASH_DERIVE_ECRNYPT_S2C_CTX),
        )?;

        Ok(Some((
            MessageEncryptor::new(make_encrypting_algo(cipher, &enc_key)?),
            MessageDecryptor::new(make_encrypting_algo(cipher, &dec_key)?),
        )))
    }

    fn preauth_hash_or<'a>(
        preauth_hash: &'a Option<PreauthHashValue>,
        else_val: &'a [u8],
    ) -> &'a [u8] {
        preauth_hash
            .as_ref()
            .map(|h| h.as_ref())
            .unwrap_or(else_val)
    }

    pub fn set_flags(
        &mut self,
        flags: SessionFlags,
        conn_info: &ConnectionInfo,
    ) -> crate::Result<()> {
        if conn_info.config.encryption_mode.is_required() && !flags.encrypt_data() {
            return Err(crate::Error::InvalidMessage(
                "Encryption is required, but not enabled for this session by the server."
                    .to_string(),
            ));
        }
        self.flags
            .set(flags)
            .map_err(|_| crate::Error::InvalidMessage("Session flags already set.".to_string()))?;
        log::debug!("Session {} flags set: {:?}", self.session_id, flags);
        Ok(())
    }

    /// Makes the session invalid, so it may not be used anymore.
    /// This should be called once a session is closed, expired, or failed setup.
    /// This function should never fail.
    pub fn invalidate(&mut self) {
        log::debug!("Invalidating session {}", self.session_id);
        self.state = Some(SessionInfoState::Invalid);
    }

    pub fn should_encrypt(&self) -> bool {
        if let Some(SessionInfoState::SetUp { algos }) = &self.state {
            algos.encryptor.is_some() && self.flags.get().map_or(false, |f| f.encrypt_data())
        } else {
            false
        }
    }

    /// Returns whether the session is set up and ready to use.

    pub fn is_set_up(&self) -> bool {
        return matches!(self.state, Some(SessionInfoState::SetUp { .. }));
    }

    pub fn is_invalid(&self) -> bool {
        return matches!(self.state, Some(SessionInfoState::Invalid));
    }

    pub fn decryptor(&self) -> Option<&MessageDecryptor> {
        match &self.state {
            Some(SessionInfoState::SetUp { algos }) => algos.decryptor.as_ref(),
            _ => None,
        }
    }

    pub fn encryptor(&self) -> Option<&MessageEncryptor> {
        match &self.state {
            Some(SessionInfoState::SetUp { algos }) => algos.encryptor.as_ref(),
            _ => None,
        }
    }

    pub fn signer(&self) -> Option<&MessageSigner> {
        match &self.state {
            Some(SessionInfoState::SetUp { algos }) => Some(&algos.signer),
            _ => None,
        }
    }
}

/// A helper struct for deriving SMB2 keys from a session key and preauth hash.
///
/// This is relevant for SMB3+ dialects.
struct KeyDeriver<'a> {
    session_key: &'a KeyToDerive,
}

impl<'a> KeyDeriver<'a> {
    #[inline]
    pub fn new(session_key: &'a KeyToDerive) -> Self {
        Self { session_key }
    }

    #[inline]
    pub fn derive(&self, label: &[u8], context: &'a [u8]) -> Result<DerivedKey, CryptoError> {
        kbkdf_hmacsha256::<16>(self.session_key, label, context)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyDeriver;

    static SESSION_KEY: [u8; 16] = [
        0xDA, 0x90, 0xB1, 0xDF, 0x80, 0x5C, 0x34, 0x9F, 0x88, 0x86, 0xBA, 0x02, 0x9E, 0xA4, 0x5C,
        0xB6,
    ];

    static PREAUTH_HASH: [u8; 64] = [
        0x47, 0x95, 0x78, 0xb1, 0x87, 0x23, 0x05, 0x6a, 0x4c, 0x3e, 0x6f, 0x73, 0x2f, 0x36, 0xf1,
        0x9c, 0xcc, 0xdd, 0x51, 0x6f, 0x49, 0x56, 0x6b, 0xa0, 0x43, 0xce, 0x59, 0x6a, 0x13, 0x42,
        0x27, 0xd9, 0x64, 0xef, 0x0a, 0xa6, 0xa6, 0x27, 0x1a, 0xfe, 0x4f, 0xe6, 0x4b, 0x4d, 0x8c,
        0xb2, 0xe6, 0xa1, 0x95, 0x11, 0xed, 0xbb, 0xf6, 0xd7, 0x7d, 0xce, 0xf0, 0x33, 0xda, 0xed,
        0x8c, 0x71, 0x81, 0xb2,
    ];

    static SIGNING_KEY: [u8; 16] = [
        0x6D, 0xAC, 0xCE, 0xDE, 0x5B, 0x4E, 0x36, 0x08, 0xAD, 0x6E, 0xA5, 0x47, 0x33, 0xCA, 0x31,
        0x63,
    ];

    #[test]
    pub fn test_key_deriver() {
        let d = KeyDeriver::new(&SESSION_KEY);
        let k = d.derive(b"SMBSigningKey\x00", &PREAUTH_HASH).unwrap();
        assert_eq!(k, SIGNING_KEY);
    }
}
