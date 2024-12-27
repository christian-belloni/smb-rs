use std::{error::Error, io::Cursor};
use binrw::prelude::*;
use aes::Aes128;
use cmac::Cmac;
use hmac::{digest::typenum, Hmac, Mac};
use rust_kbkdf::{kbkdf, CounterMode, InputType, KDFMode, PseudoRandomFunction, PseudoRandomFunctionKey, SpecifiedInput};
use sha2::Sha256;

use crate::packets::{netbios::NetBiosTcpMessage, smb2::header::SMB2MessageHeader};


pub struct SMBSession {
    signing_key: [u8; 16],
}

impl SMBSession {
    pub fn build(exchanged_session_key: &Vec<u8>, preauth_integrity_hash: [u8; 64]) -> Result<SMBSession, Box<dyn Error>> {

        Ok(SMBSession {
            signing_key: Self::derive_signing_key(exchanged_session_key, preauth_integrity_hash)?
        })
    }

    pub fn verify_signature(&self, header: &mut SMB2MessageHeader, raw_data: &NetBiosTcpMessage) -> Result<(), Box<dyn Error>> {
        let calculated_signature = self.calculate_signature(header, raw_data)?;
        if calculated_signature != header.signature {
            return Err("Signature verification failed".into());
        }
        Ok(())
    }

    pub fn sign_message(&self, header: &mut SMB2MessageHeader, raw_data: &mut NetBiosTcpMessage) -> Result<(), Box<dyn Error>> {
        header.signature = self.calculate_signature(header, raw_data)?;
        // Update raw data to include the signature.
        let mut header_writer = Cursor::new(&mut raw_data.content[0..SMB2MessageHeader::STRUCT_SIZE]);
        header.write(&mut header_writer)?;
        Ok(())
    }

    fn calculate_signature(&self, header: &mut SMB2MessageHeader, raw_message: &NetBiosTcpMessage) -> Result<u128, Box<dyn Error>> {
        // in-place.
        let mut signing_algo = SMBCmac128Signer::build(&self.signing_key)?;

        // Write header.
        let signture_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; SMB2MessageHeader::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signture_backup;
        signing_algo.update(&header_bytes.into_inner());

        // And write rest of the raw message.
        let message_body = &raw_message.content[SMB2MessageHeader::STRUCT_SIZE..];
        signing_algo.update(message_body);

        Ok(signing_algo.finalize())
    }

    fn derive_signing_key(exchanged_session_key: &Vec<u8>, preauth_integrity_hash: [u8; 64]) -> Result<[u8; 16], Box<dyn Error>> {
        let mut session_key = [0; 16];
        session_key.copy_from_slice(&exchanged_session_key[0..16]);

        // Label = SMBSigningKey\x00
        let label = b"SMBSigningKey\x00";
        assert!(session_key.len() == 16);
        Ok(Self::kbkdf_hmacsha256(&session_key, label, &preauth_integrity_hash)?.try_into().unwrap())
    }

    fn kbkdf_hmacsha256(key: &[u8; 16], label: &[u8], context: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // SP108-800-CTR-HMAC-SHA256; 128 bits; 32-bit counter.
        let key = HmacSha256KeyHandle {
            key: key.clone(),
        };

        let mut prf = HmacSha256Prf::default();
        let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });

        let input = InputType::SpecifiedInput(SpecifiedInput {
            label,
            context,
        });

        let mut output = vec![0; 128 / 8];
        kbkdf(&mode, &input, &key, &mut prf, &mut output)?;

        Ok(output)
    }

    pub fn signing_enabled(&self) -> bool {
        true
    }
}

type HmacSha256 = Hmac<Sha256>;

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
    hmac: Option<HmacSha256>
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

pub trait SMBSigningAlgo {
    fn build(signing_key: &[u8; 16]) -> Result<Box<Self>, Box<dyn Error>>;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> u128;
}

struct SMBCmac128Signer {
    cmac: Cmac<Aes128>,
}

impl SMBSigningAlgo for SMBCmac128Signer {
    fn build(signing_key: &[u8; 16]) -> Result<Box<Self>, Box<dyn Error>> {
        Ok(Box::new(SMBCmac128Signer {
            cmac: Cmac::new_from_slice(signing_key)?
        }))
    }

    fn update(&mut self, data: &[u8]) {
        self.cmac.update(data);
    }

    fn finalize(self) -> u128 {
        u128::from_le_bytes(self.cmac.finalize().into_bytes().into())
    }
}