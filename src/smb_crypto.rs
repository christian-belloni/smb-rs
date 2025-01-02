use std::{error::Error, fmt::Debug};

use aes::{cipher::typenum, Aes128};
use cmac::Cmac;
use hmac::{Hmac, Mac};
use rust_kbkdf::{
    kbkdf, CounterMode, InputType, KDFMode, PseudoRandomFunction, PseudoRandomFunctionKey,
    SpecifiedInput,
};
use sha2::Sha256;

use crate::packets::smb2::{message::SMB2Message, negotiate::SigningAlgorithmId};

type HmacSha256 = Hmac<Sha256>;

pub struct SMBCrypto;

impl SMBCrypto {
    pub fn kbkdf_hmacsha256(
        key: &[u8; 16],
        label: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // SP108-800-CTR-HMAC-SHA256; 128 bits; 32-bit counter.
        let key = HmacSha256KeyHandle { key: key.clone() };

        let mut prf = HmacSha256Prf::default();
        let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });

        let input = InputType::SpecifiedInput(SpecifiedInput { label, context });

        let mut output = vec![0; 128 / 8];
        kbkdf(&mode, &input, &key, &mut prf, &mut output)?;

        Ok(output)
    }

    pub fn make_signing_algo(
        signing_algorithm: SigningAlgorithmId,
        signing_key: &[u8; 16],
        message: &SMB2Message,
    ) -> Result<Box<dyn SMBSigningAlgo>, Box<dyn Error>> {
        if !Self::SIGNING_ALGOS.contains(&signing_algorithm) {
            return Err(format!("Unsupported signing algorithm {:?}", signing_algorithm).into());
        }
        match signing_algorithm {
            SigningAlgorithmId::AesCmac => Ok(SMBCmac128Signer::build(signing_key)?),
            SigningAlgorithmId::AesGmac => Ok(gmac::SMBGmac128Signer::new(signing_key, message)),
            _ => Err("Unsupported signing algorithm".into()),
        }
    }

    pub const SIGNING_ALGOS: [SigningAlgorithmId; 2] =
        [SigningAlgorithmId::AesCmac, SigningAlgorithmId::AesGmac];
}

struct HmacSha256KeyHandle {
    key: [u8; 16],
}

impl PseudoRandomFunctionKey for HmacSha256KeyHandle {
    type KeyHandle = [u8; 16];

    fn key_handle(&self) -> &Self::KeyHandle {
        &self.key
    }
}

#[derive(Default)]
struct HmacSha256Prf {
    hmac: Option<HmacSha256>,
}

impl PseudoRandomFunction<'_> for HmacSha256Prf {
    type KeyHandle = [u8; 16];

    type PrfOutputSize = typenum::U32;

    type Error = String;

    fn init(
        &mut self,
        key: &'_ dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Self::Error> {
        assert!(self.hmac.is_none());
        self.hmac = Some(HmacSha256::new_from_slice(key.key_handle()).unwrap());
        Ok(())
    }

    fn update(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        self.hmac.as_mut().unwrap().update(msg);
        Ok(())
    }

    fn finish(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        let result = self.hmac.take().unwrap().finalize().into_bytes();
        out.copy_from_slice(&result);
        Ok(result.len())
    }
}

pub trait SMBSigningAlgo: Debug {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> u128;
}

#[derive(Debug)]
struct SMBCmac128Signer {
    cmac: Option<Cmac<Aes128>>,
}

impl SMBCmac128Signer {
    fn build(signing_key: &[u8; 16]) -> Result<Box<dyn SMBSigningAlgo>, Box<dyn Error>> {
        Ok(Box::new(SMBCmac128Signer {
            cmac: Some(Cmac::new_from_slice(signing_key)?),
        }))
    }
}

impl SMBSigningAlgo for SMBCmac128Signer {
    fn update(&mut self, data: &[u8]) {
        self.cmac.as_mut().unwrap().update(data);
    }

    fn finalize(&mut self) -> u128 {
        u128::from_le_bytes(self.cmac.take().unwrap().finalize().into_bytes().into())
    }
}

mod gmac {

    use aes::Aes128;
    use aes_gcm::{
        aead::{AeadMutInPlace, KeyInit},
        Aes128Gcm, Key,
    };
    use binrw::prelude::*;
    use modular_bitfield::prelude::*;

    use crate::packets::smb2::{header::SMB2Command, message::SMB2Message};

    use super::*;

    pub struct SMBGmac128Signer {
        gmac: Aes128Gcm,
        nonce: [u8; 12],
        // no online mode implemented un RustCrypto,
        // so we'll buffer the input until finalized().
        buffer: Vec<u8>,
    }

    #[bitfield]
    #[derive(BinWrite, BinRead, Debug, Clone, Copy)]
    #[bw(map = |&x| Self::into_bytes(x))]
    struct NonceSuffixFlags {
        is_server: bool,
        is_cancel: bool,
        zero: B30,
    }

    impl SMBGmac128Signer {
        pub fn new(key: &[u8; 16], message: &SMB2Message) -> Box<dyn SMBSigningAlgo> {
            let key = Key::<Aes128>::from_slice(key);
            Box::new(SMBGmac128Signer {
                gmac: Aes128Gcm::new(&key),
                nonce: Self::make_nonce(&message),
                buffer: vec![],
            })
        }

        fn make_nonce(message: &SMB2Message) -> [u8; 12] {
            let mut result: [u8; 12] = [0; 12];
            // First 8 bytes are message ID.
            debug_assert!(message.header.message_id > 0);
            result[0..8].copy_from_slice(&message.header.message_id.to_le_bytes());
            // Following 4 bytes -- flags as followed:
            let b = NonceSuffixFlags::new()
                .with_is_cancel(message.content.associated_cmd() == SMB2Command::Cancel)
                .with_is_server(false)
                .bytes;
            debug_assert!(b.len() == 4);
            result[8..].copy_from_slice(&b);

            return result;
        }
    }

    impl super::SMBSigningAlgo for SMBGmac128Signer {
        fn update(&mut self, data: &[u8]) {
            // Currently buffered until finalized.
            self.buffer.extend_from_slice(data);
        }

        fn finalize(&mut self) -> u128 {
            let result = self
                .gmac
                .encrypt_in_place_detached(self.nonce.as_ref().into(), b"", &mut self.buffer)
                .unwrap();
            u128::from_le_bytes(result.into())
        }
    }

    impl Debug for SMBGmac128Signer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SMBGmac128Signer").finish()
        }
    }
}
