use aes::{Aes128, Aes256};
use ccm::{
    aead::{generic_array::GenericArray, AeadMutInPlace, KeyInit},
    consts::{U11, U16},
    Ccm,
};
use std::{error::Error, fmt::Debug};

use crate::packets::smb2::negotiate::EncryptionCipher;

pub struct EncryptionResult {
    pub signature: [u8; 16],
}

pub trait EncryptingAlgo: Debug {
    fn encrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &[u8],
    ) -> Result<EncryptionResult, Box<dyn Error>>;

    fn decrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &[u8],
        signature: &[u8; 16],
    ) -> Result<(), Box<dyn Error>>;

    fn nonce_size(&self) -> usize;
}

pub const ENCRYPTING_ALGOS: [EncryptionCipher; 1] = [EncryptionCipher::Aes128Ccm];

pub fn make_encrypting_algo(
    encrypting_algorithm: EncryptionCipher,
    encrypting_key: &[u8; 16],
) -> Result<Box<dyn EncryptingAlgo>, Box<dyn Error>> {
    if !ENCRYPTING_ALGOS.contains(&encrypting_algorithm) {
        return Err(format!(
            "Unsupported encrypting algorithm {:?}",
            encrypting_algorithm
        )
        .into());
    }
    match encrypting_algorithm {
        EncryptionCipher::Aes128Ccm => Ok(Ccm128Encrypter::build(encrypting_key)?),
        _ => Err("Unsupported encrypting algorithm".into()),
    }
}

type Aes128Ccm = Ccm<Aes128, U16, U11>;
type Aes256Ccm = Ccm<Aes256, U16, U11>;

pub struct Ccm128Encrypter {
    cipher: Aes128Ccm,
}

impl Ccm128Encrypter {
    fn build(encrypting_key: &[u8; 16]) -> Result<Box<dyn EncryptingAlgo>, Box<dyn Error>> {
        Ok(Box::new(Ccm128Encrypter {
            cipher: Aes128Ccm::new_from_slice(encrypting_key.as_ref())?,
        }))
    }
}

impl EncryptingAlgo for Ccm128Encrypter {
    fn encrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &[u8],
    ) -> Result<EncryptionResult, Box<dyn Error>> {
        let nonce = GenericArray::from_slice(&nonce);
        let signature = self
            .cipher
            .encrypt_in_place_detached(nonce, header_data, payload)?;

        Ok(EncryptionResult {
            signature: signature.try_into()?,
        })
    }

    fn decrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &[u8],
        signature: &[u8; 16],
    ) -> Result<(), Box<dyn Error>> {
        let nonce = GenericArray::from_slice(&nonce);
        self.cipher
            .decrypt_in_place_detached(nonce, header_data, payload, signature.into())?;

        Ok(())
    }

    fn nonce_size(&self) -> usize {
        11
    }
}

impl Debug for Ccm128Encrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ccm128Encrypter")
    }
}
