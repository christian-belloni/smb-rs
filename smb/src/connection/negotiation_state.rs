use crate::packets::guid::Guid;
use crate::packets::smb2::*;
use binrw::prelude::*;

#[derive(Debug)]
pub struct NegotiateState {
    pub server_guid: Guid,

    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,

    pub gss_token: Vec<u8>,

    pub selected_dialect: Dialect,

    pub signing_algo: SigningAlgorithmId,
    pub encryption_cipher: EncryptionCipher,
    pub compression: Option<CompressionCaps>,
}

impl NegotiateState {
    pub fn gss_token(&self) -> &[u8] {
        &self.gss_token
    }

    pub fn signing_algo(&self) -> SigningAlgorithmId {
        self.signing_algo
    }

    pub fn cipher(&self) -> EncryptionCipher {
        self.encryption_cipher
    }
}
