use std::sync::Arc;

use crate::dialects::DialectImpl;
use crate::packets::guid::Guid;
use crate::packets::smb2::*;
use binrw::prelude::*;

use super::ConnectionConfig;

#[derive(Debug)]
pub struct NegotiatedProperties {
    pub server_guid: Guid,

    pub caps: GlobalCapabilities,

    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,

    pub gss_token: Vec<u8>,

    pub signing_algo: Option<SigningAlgorithmId>,
    pub encryption_cipher: Option<EncryptionCipher>,
    pub compression: Option<CompressionCaps>,

    pub dialect_rev: Dialect,
}

impl NegotiatedProperties {
    pub fn gss_token(&self) -> &[u8] {
        &self.gss_token
    }

    pub fn signing_algo(&self) -> Option<SigningAlgorithmId> {
        self.signing_algo
    }

    pub fn cipher(&self) -> Option<EncryptionCipher> {
        self.encryption_cipher
    }
}

#[derive(Debug)]
pub struct ConnectionInfo {
    pub state: NegotiatedProperties,
    pub dialect: Arc<DialectImpl>,
    pub config: ConnectionConfig,
}
