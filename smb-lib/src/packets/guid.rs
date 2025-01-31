use std::fmt::Display;

use binrw::prelude::*;
use rand::{rngs::OsRng, Rng};

/// Represents a standard, 16-byte GUID.
#[derive(BinRead, BinWrite, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(u128);

impl Guid {
    pub fn new() -> Self {
        Self { 0: OsRng.gen() }
    }

    pub const MAX: Guid = Guid { 0: u128::MAX };
}

impl From<u128> for Guid {
    fn from(value: u128) -> Self {
        Self { 0: value }
    }
}

impl From<[u8; 16]> for Guid {
    fn from(value: [u8; 16]) -> Self {
        u128::from_le_bytes(value).into()
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            (self.0 >> 96) & 0xffff_ffff,
            (self.0 >> 80) & 0xffff,
            (self.0 >> 64) & 0xffff,
            (self.0 >> 48) & 0xffff,
            self.0 & 0xffff_ffff_ffff,
        )
    }
}
