use binrw::prelude::*;
use rand::{rngs::OsRng, Rng};

#[derive(Debug, BinRead, BinWrite, Clone, Copy)]
pub struct Guid {
    value: u128,
}

impl Guid {
    pub fn new() -> Self {
        Self { value: OsRng.gen() }
    }
}
