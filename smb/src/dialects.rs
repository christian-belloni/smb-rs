//! Implements SMB-dialect-specific types and functions.

use std::sync::Arc;

use crate::{
    connection::{negotiation_state::NegotiateState, preauth_hash},
    crypto,
    packets::smb2::{
        CompressionCaps, Dialect, GlobalCapabilities, NegotiateResponse, SigningAlgorithmId,
    },
    Error,
};

pub trait DialectImpl: std::fmt::Debug + Send + Sync {
    fn get_dialect(&self) -> Dialect;
    fn get_negotiate_caps_mask(&self) -> GlobalCapabilities;
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        state: &mut NegotiateState,
    ) -> crate::Result<()>;

    fn get_signing_nonce(&self) -> &[u8];
    fn preauth_hash_supported(&self) -> bool;
    fn default_signing_algo(&self) -> SigningAlgorithmId {
        SigningAlgorithmId::HmacSha256
    }

    fn supports_compression(&self) -> bool {
        false
    }

    fn supports_encryption(&self) -> bool {
        false
    }
}

/// Get the dialect implementation for the given dialect.
pub fn get_dialect_impl(dialect: &Dialect) -> Arc<dyn DialectImpl> {
    match dialect {
        Dialect::Smb0311 => Arc::new(Smb0311Dialect),
        Dialect::Smb0302 => Arc::new(Smb302Dialect),
        _ => unimplemented!(),
    }
}

#[derive(Debug)]
struct Smb0311Dialect;

impl DialectImpl for Smb0311Dialect {
    fn get_dialect(&self) -> Dialect {
        Dialect::Smb0311
    }

    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        state: &mut NegotiateState,
    ) -> crate::Result<()> {
        if let None = response.negotiate_context_list {
            return Err(Error::InvalidMessage(
                "Expected negotiate context list".to_string(),
            ));
        }

        let signing_algo = if let Some(signing_algo) = response.get_ctx_signing_algo() {
            if !crypto::SIGNING_ALGOS.contains(&signing_algo) {
                return Err(Error::NegotiationError(
                    "Unsupported signing algorithm selected!".into(),
                ));
            }
            Some(signing_algo)
        } else {
            None
        };

        // Make sure preauth integrity capability is SHA-512, if it exists in response:
        if let Some(algo) = response.get_ctx_integrity_algo() {
            if !preauth_hash::SUPPORTED_ALGOS.contains(&algo) {
                return Err(Error::NegotiationError(
                    "Unsupported preauth integrity algorithm received".into(),
                ));
            }
        }

        // And verify that the encryption algorithm is supported.
        let encryption_cipher = response.get_ctx_encrypt_cipher();
        if let Some(encryption_cipher) = &encryption_cipher {
            if !crypto::ENCRYPTING_ALGOS.contains(&encryption_cipher) {
                return Err(Error::NegotiationError(
                    "Unsupported encryption algorithm received".into(),
                ));
            }
        }

        let compression: Option<CompressionCaps> = match response.get_ctx_compression() {
            Some(compression) => Some(compression.clone()),
            None => None,
        };

        state.signing_algo = signing_algo;
        state.encryption_cipher = encryption_cipher;
        state.compression = compression;

        Ok(())
    }

    fn get_negotiate_caps_mask(&self) -> GlobalCapabilities {
        GlobalCapabilities::new()
            .with_dfs(true)
            .with_leasing(true)
            .with_large_mtu(true)
            .with_multi_channel(true)
            .with_persistent_handles(true)
            .with_directory_leasing(true)
            .with_encryption(false)
            .with_notifications(true)
    }

    fn get_signing_nonce(&self) -> &[u8] {
        b"SMBSigningKey\x00"
    }

    fn preauth_hash_supported(&self) -> bool {
        true
    }

    fn default_signing_algo(&self) -> SigningAlgorithmId {
        SigningAlgorithmId::AesCmac
    }

    fn supports_compression(&self) -> bool {
        true
    }
    fn supports_encryption(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct Smb302Dialect;

impl DialectImpl for Smb302Dialect {
    fn get_dialect(&self) -> Dialect {
        Dialect::Smb0302
    }

    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        _state: &mut NegotiateState,
    ) -> crate::Result<()> {
        if response.negotiate_context_list.is_some() {
            return Err(Error::InvalidMessage(
                "Negotiate context list not expected".to_string(),
            ));
        }

        Ok(())
    }

    fn get_negotiate_caps_mask(&self) -> GlobalCapabilities {
        GlobalCapabilities::new()
            .with_dfs(true)
            .with_leasing(true)
            .with_large_mtu(true)
            .with_multi_channel(true)
            .with_persistent_handles(true)
            .with_directory_leasing(true)
            .with_encryption(true)
            .with_notifications(false)
    }

    fn get_signing_nonce(&self) -> &[u8] {
        b"SMB2AESCMAC\x00"
    }

    fn preauth_hash_supported(&self) -> bool {
        false
    }

    fn default_signing_algo(&self) -> SigningAlgorithmId {
        SigningAlgorithmId::AesCmac
    }

    fn supports_encryption(&self) -> bool {
        true
    }
}
