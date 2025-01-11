use std::{error::Error, fmt::Debug};

use aes::{cipher::typenum, Aes128};
use cmac::Cmac;
use hmac::{Hmac, Mac};
use rust_kbkdf::{
    kbkdf, CounterMode, InputType, KDFMode, PseudoRandomFunction, PseudoRandomFunctionKey,
    SpecifiedInput,
};
use sha2::Sha256;

use crate::packets::smb2::{
    header::SMB2MessageHeader, message::SMB2Message, negotiate::SigningAlgorithmId,
};

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
    ) -> Result<Box<dyn SMBSigningAlgo>, Box<dyn Error>> {
        if !Self::SIGNING_ALGOS.contains(&signing_algorithm) {
            return Err(format!("Unsupported signing algorithm {:?}", signing_algorithm).into());
        }
        match signing_algorithm {
            SigningAlgorithmId::AesCmac => Ok(SMBCmac128Signer::build(signing_key)?),
            SigningAlgorithmId::AesGmac => Ok(gmac::SMBGmac128Signer::new(signing_key)),
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

/// A trait for SMB signing algorithms.
pub trait SMBSigningAlgo: Debug {
    /// Start a new signing session. This is called before any data is passed to the signer,
    /// and [SMBSigningAlgo::update] must feed the header data to the signer, in addition to this call.
    ///
    /// An algorithm may implement this function to perform any necessary initialization,
    /// that requires the header data.
    /// This function must be called once per signing session.
    fn start(&mut self, _header: &SMB2MessageHeader) {
        // Default implementation does nothing.
    }

    /// Update the signing session with new data.
    fn update(&mut self, data: &[u8]);

    /// Finalize the signing session and return the signature.
    ///
    /// This function must be called once per signing session.
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

    use std::cell::OnceCell;

    use aes::Aes128;
    use aes_gcm::{
        aead::{AeadMutInPlace, KeyInit},
        Aes128Gcm, Key,
    };
    use binrw::prelude::*;
    use modular_bitfield::prelude::*;

    use crate::packets::smb2::header::SMB2Command;

    use super::*;

    pub struct SMBGmac128Signer {
        gmac: Aes128Gcm,
        nonce: OnceCell<[u8; 12]>,
        // no online mode implemented un RustCrypto,
        // so we'll buffer the input until finalized().
        buffer: Vec<u8>,
    }

    #[bitfield]
    struct NonceSuffixFlags {
        #[allow(unused)]
        pub msg_id: B64,
        #[allow(unused)]
        pub is_server: bool,
        #[allow(unused)]
        pub is_cancel: bool,
        #[skip]
        __: B30,
    }

    impl SMBGmac128Signer {
        pub fn new(key: &[u8; 16]) -> Box<dyn SMBSigningAlgo> {
            let key = Key::<Aes128>::from_slice(key);
            Box::new(SMBGmac128Signer {
                gmac: Aes128Gcm::new(&key),
                nonce: OnceCell::new(),
                buffer: vec![],
            })
        }

        fn make_nonce(header: &SMB2MessageHeader) -> [u8; 12] {
            debug_assert!(header.message_id > 0 && header.message_id != u64::MAX);

            return NonceSuffixFlags::new()
                .with_msg_id(header.message_id)
                .with_is_cancel(header.command == SMB2Command::Cancel)
                .with_is_server(header.flags.server_to_redir())
                .into_bytes()
                .into();
        }
    }

    impl super::SMBSigningAlgo for SMBGmac128Signer {
        fn start(&mut self, header: &SMB2MessageHeader) {
            // The nonce is derived from the message ID.
            self.nonce.set(Self::make_nonce(header)).unwrap();
        }

        fn update(&mut self, data: &[u8]) {
            debug_assert!(self.nonce.get().is_some());

            // Currently buffered until finalized.
            self.buffer.extend_from_slice(data);
        }

        fn finalize(&mut self) -> u128 {
            debug_assert!(self.nonce.get().is_some());

            let mut empty_data: Vec<u8> = vec![];
            let result = self
                .gmac
                .encrypt_in_place_detached(
                    self.nonce.get().unwrap().into(),
                    &self.buffer,
                    &mut empty_data,
                )
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
