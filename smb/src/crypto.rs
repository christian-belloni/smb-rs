mod encryption;
mod kbkdf;
mod signing;

pub use encryption::{make_encrypting_algo, EncryptingAlgo, ENCRYPTING_ALGOS};
pub use kbkdf::{kbkdf_hmacsha256, DerivedKey, KeyToDerive};
pub use signing::{make_signing_algo, SigningAlgo, SIGNING_ALGOS};

use crypto_common::InvalidLength;
use thiserror::Error;

use crate::packets::smb2::{EncryptionCipher, SigningAlgorithmId};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid length")]
    InvalidLength(#[from] InvalidLength),
    #[error("Unsupported encryption algorithm {0:?}")]
    UnsupportedEncryptionAlgorithm(EncryptionCipher),
    #[error("Unsupported signing algorithm")]
    UnsupportedSigningAlgorithm(SigningAlgorithmId),
    #[cfg(any(
        feature = "encrypt_aes128ccm",
        feature = "encrypt_aes256ccm",
        feature = "encrypt_aes128gcm",
        feature = "encrypt_aes256gcm"
    ))]
    #[error("AEAD calculation error")]
    AeadError(#[from] aead::Error),
}
