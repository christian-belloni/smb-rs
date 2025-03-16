//! Implements SMB-dialect-specific types and functions.

use std::sync::Arc;

use crate::{
    connection::{connection_info::NegotiatedProperties, preauth_hash},
    crypto,
    packets::smb2::{
        CompressionCaps, Dialect, GlobalCapabilities, NegotiateResponse, SigningAlgorithmId,
        TreeCapabilities, TreeConnectShareFlagsCacheMode, TreeShareFlags,
    },
    ConnectionConfig, Error,
};

/// This is a utility struct that returns constants and functions for the given dialect.
#[derive(Debug)]
pub struct DialectImpl {
    pub dialect: Dialect,
}

impl DialectImpl {
    pub fn new(dialect: Dialect) -> Arc<Self> {
        Arc::new(Self { dialect })
    }

    pub fn get_negotiate_caps_mask(&self) -> GlobalCapabilities {
        let mut mask = GlobalCapabilities::new()
            .with_dfs(true)
            .with_leasing(true)
            .with_large_mtu(true)
            .with_multi_channel(true)
            .with_persistent_handles(true)
            .with_directory_leasing(true);

        mask.set_encryption(Dialect::Smb030 <= self.dialect && self.dialect <= Dialect::Smb0302);
        mask.set_notifications(self.dialect == Dialect::Smb0311);

        mask
    }

    pub fn get_share_flags_mask(&self) -> TreeShareFlags {
        let mut mask = TreeShareFlags::new()
            .with_caching_mode(TreeConnectShareFlagsCacheMode::All)
            .with_dfs(true)
            .with_dfs_root(true)
            .with_restrict_exclusive_opens(true)
            .with_force_shared_delete(true)
            .with_allow_namespace_caching(true)
            .with_access_based_directory_enum(true)
            .with_force_levelii_oplock(true)
            .with_identity_remoting(true)
            .with_isolated_transport(true);

        if self.dialect > Dialect::Smb0202 {
            mask.set_enable_hash_v1(true);
        }
        if self.dialect >= Dialect::Smb021 {
            mask.set_enable_hash_v2(true);
        }
        if self.dialect.is_smb3() {
            mask.set_encrypt_data(true);
        }
        if self.dialect >= Dialect::Smb0311 {
            mask.set_compress_data(true);
        }

        mask
    }

    pub fn get_tree_connect_caps_mask(&self) -> TreeCapabilities {
        let mut mask = TreeCapabilities::new().with_dfs(true);

        if self.dialect.is_smb3() {
            mask = mask
                .with_continuous_availability(true)
                .with_scaleout(true)
                .with_cluster(true);
        }

        if self.dialect >= Dialect::Smb0302 {
            mask.set_asymmetric(true);
        }

        if self.dialect == Dialect::Smb0311 {
            mask = mask.with_redirect_to_owner(true);
        }

        mask
    }

    pub fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()> {
        match self.dialect {
            Dialect::Smb0311 => Smb311.process_negotiate_request(response, state, config),
            Dialect::Smb0302 | Dialect::Smb030 => {
                Smb300_302.process_negotiate_request(response, state, config)
            }
            _ => unimplemented!(),
        }
    }

    pub fn get_signing_derive_label(&self) -> &[u8] {
        match self.dialect {
            Dialect::Smb0311 => Smb311::SIGNING_KEY_LABEL,
            Dialect::Smb0302 | Dialect::Smb030 => Smb300_302::SIGNING_KEY_LABEL,
            _ => unimplemented!(),
        }
    }
    pub fn preauth_hash_supported(&self) -> bool {
        self.dialect == Dialect::Smb0311
    }
    pub fn default_signing_algo(&self) -> SigningAlgorithmId {
        match self.dialect {
            Dialect::Smb0311 | Dialect::Smb0302 | Dialect::Smb030 => SigningAlgorithmId::AesCmac,
            Dialect::Smb0202 | Dialect::Smb021 => SigningAlgorithmId::HmacSha256,
        }
    }

    pub fn supports_compression(&self) -> bool {
        self.dialect == Dialect::Smb0311
    }

    pub fn supports_encryption(&self) -> bool {
        self.dialect.is_smb3()
    }

    pub fn s2c_encrypt_key_derive_label(&self) -> &[u8] {
        match self.dialect {
            Dialect::Smb0311 => Smb311::ENCRYPTION_S2C_KEY_LABEL,
            Dialect::Smb0302 | Dialect::Smb030 => Smb300_302::ENCRYPTION_KEY_LABEL,
            _ => panic!("Encryption is not supported for this dialect!"),
        }
    }
    pub fn c2s_encrypt_key_derive_label(&self) -> &[u8] {
        match self.dialect {
            Dialect::Smb0311 => Smb311::ENCRYPTION_C2S_KEY_LABEL,
            Dialect::Smb0302 | Dialect::Smb030 => Smb300_302::ENCRYPTION_KEY_LABEL,
            _ => panic!("Encryption is not supported for this dialect!"),
        }
    }
}

trait DialectMethods {
    const SIGNING_KEY_LABEL: &[u8];
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        _state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()>;
}

struct Smb311;
impl Smb311 {
    pub const ENCRYPTION_S2C_KEY_LABEL: &[u8] = b"SMBS2CCipherKey\x00";
    pub const ENCRYPTION_C2S_KEY_LABEL: &[u8] = b"SMBC2SCipherKey\x00";
}

impl DialectMethods for Smb311 {
    const SIGNING_KEY_LABEL: &[u8] = b"SMBSigningKey\x00";
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
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
        } else if config.encryption_mode.is_required() {
            return Err(Error::NegotiationError(
                "Encryption is required, but no algorithms provided by the server".into(),
            ));
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
}

struct Smb300_302;
impl Smb300_302 {
    pub const ENCRYPTION_KEY_LABEL: &[u8] = b"SMB2AESCCM\x00";
}

impl DialectMethods for Smb300_302 {
    const SIGNING_KEY_LABEL: &[u8] = b"SMB2AESCMAC\x00";
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        _state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()> {
        if response.negotiate_context_list.is_some() {
            return Err(Error::InvalidMessage(
                "Negotiate context list not expected".to_string(),
            ));
        }

        if config.encryption_mode.is_required() && !response.capabilities.encryption() {
            return Err(Error::NegotiationError(
                "Encryption is required, but cap not supported by the server.".into(),
            ));
        }

        Ok(())
    }
}
