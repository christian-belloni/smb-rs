mod encryption;
mod kbkdf;
mod signing;

pub use encryption::{make_encrypting_algo, EncryptingAlgo, ENCRYPTING_ALGOS};
pub use kbkdf::{kbkdf_hmacsha256, DerivedKey, KeyToDerive};
pub use signing::{make_signing_algo, SigningAlgo, SIGNING_ALGOS};

use crypto_common::InvalidLength;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid length")]
    InvalidLength(#[from] InvalidLength),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("AEAD calculation error")]
    AeadError(#[from] aead::Error),
}
