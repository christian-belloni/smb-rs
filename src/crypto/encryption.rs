use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockEncrypt, BlockSizeUser},
    Aes128, Aes256,
};
use ccm::{
    aead::AeadMutInPlace,
    consts::{U11, U16},
    Ccm, KeyInit, KeySizeUser,
};
use std::{error::Error, fmt::Debug};

use crate::packets::smb2::{encrypted::EncryptionNonce, negotiate::EncryptionCipher};

pub struct EncryptionResult {
    pub signature: u128,
}

pub trait EncryptingAlgo: Debug {
    /// Algo-specific encryption function.
    fn encrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
    ) -> Result<EncryptionResult, Box<dyn Error>>;

    /// Algo-specific decryption function.
    fn decrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
        signature: u128,
    ) -> Result<(), Box<dyn Error>>;

    /// Returns the size of the nonce required by the encryption algorithm.
    fn nonce_size(&self) -> usize;

    /// Returns the nonce to be used for encryption/decryption (trimmed to the required size),
    /// as the rest of the nonce is expected to be zero.
    fn trim_nonce<'a>(&self, nonce: &'a EncryptionNonce) -> &'a [u8] {
        // Sanity: the rest of the nonce is expected to be zero.
        debug_assert!(nonce[self.nonce_size()..].iter().all(|&x| x == 0));
        &nonce[..self.nonce_size()]
    }
}

pub const ENCRYPTING_ALGOS: [EncryptionCipher; 1] = [EncryptionCipher::Aes128Ccm];

pub fn make_encrypting_algo(
    encrypting_algorithm: EncryptionCipher,
    encrypting_key: &[u8],
) -> Result<Box<dyn EncryptingAlgo>, Box<dyn Error>> {
    if !ENCRYPTING_ALGOS.contains(&encrypting_algorithm) {
        return Err(format!(
            "Unsupported encrypting algorithm {:?}",
            encrypting_algorithm
        )
        .into());
    }
    match encrypting_algorithm {
        EncryptionCipher::Aes128Ccm => Ok(CcmEncryptor::<Aes128>::build(encrypting_key.into())?),
        EncryptionCipher::Aes256Ccm => Ok(CcmEncryptor::<Aes256>::build(encrypting_key.into())?),
        _ => Err("Unsupported encrypting algorithm".into()),
    }
}

pub struct CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    cipher: Ccm<C, U16, U11>,
}

impl<C> CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit + 'static,
{
    fn build(
        encrypting_key: &GenericArray<u8, <C as KeySizeUser>::KeySize>,
    ) -> Result<Box<dyn EncryptingAlgo>, Box<dyn Error>> {
        Ok(Box::new(Self {
            cipher: Ccm::<C, U16, U11>::new_from_slice(encrypting_key)?,
        }))
    }
}

impl<C> EncryptingAlgo for CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn encrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
    ) -> Result<EncryptionResult, Box<dyn Error>> {
        let nonce = GenericArray::from_slice(self.trim_nonce(nonce));
        let signature = self
            .cipher
            .encrypt_in_place_detached(nonce, header_data, payload)?;

        Ok(EncryptionResult {
            signature: u128::from_le_bytes(signature.into()),
        })
    }

    fn decrypt(
        &mut self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
        signature: u128,
    ) -> Result<(), Box<dyn Error>> {
        let nonce = GenericArray::from_slice(self.trim_nonce(nonce));
        self.cipher.decrypt_in_place_detached(
            nonce,
            header_data,
            payload,
            &signature.to_le_bytes().into(),
        )?;

        Ok(())
    }

    fn nonce_size(&self) -> usize {
        11
    }
}

impl<C> Debug for CcmEncryptor<C>
where
    C: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ccm128Encrypter")
    }
}
