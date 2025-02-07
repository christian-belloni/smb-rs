use crate::compression::{Compressor, Decompressor};

use crate::packets::guid::Guid;
use crate::packets::smb2::*;
use binrw::prelude::*;

#[derive(Debug)]
pub struct SmbNegotiateState {
    pub server_guid: Guid,

    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,

    pub gss_negotiate_token: Vec<u8>,

    pub selected_dialect: Dialect,
    pub signing_algo: SigningAlgorithmId,
    pub compressor: Option<Compressor>,
    pub decompressor: Option<Decompressor>,
}

impl SmbNegotiateState {
    pub fn get_gss_token(&self) -> &[u8] {
        &self.gss_negotiate_token
    }

    pub fn get_signing_algo(&self) -> SigningAlgorithmId {
        self.signing_algo
    }
}
