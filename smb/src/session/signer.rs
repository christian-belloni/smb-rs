//! SMB Message signing implementation.

use binrw::prelude::*;
use std::{error::Error, io::Cursor};

use crate::{crypto, packets::smb2::header::Header};

#[derive(Debug)]
pub struct MessageSigner {
    signing_algo: Box<dyn crypto::SigningAlgo>,
}

impl MessageSigner {
    pub fn new(signing_algo: Box<dyn crypto::SigningAlgo>) -> MessageSigner {
        MessageSigner { signing_algo }
    }

    pub fn verify_signature(
        &mut self,
        header: &mut Header,
        raw_data: &Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        let calculated_signature = self.calculate_signature(header, raw_data)?;
        if calculated_signature != header.signature {
            return Err("Signature verification failed".into());
        }
        log::debug!(
            "Signature verification passed (signature={}).",
            header.signature
        );
        Ok(())
    }

    pub fn sign_message(
        &mut self,
        header: &mut Header,
        raw_data: &mut Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        debug_assert!(raw_data.len() >= Header::STRUCT_SIZE);

        header.signature = self.calculate_signature(header, raw_data)?;
        // Update raw data to include the signature.
        let mut header_writer = Cursor::new(&mut raw_data[0..Header::STRUCT_SIZE]);
        header.write(&mut header_writer)?;

        log::debug!(
            "Message #{} signed (signature={}).",
            header.message_id,
            header.signature
        );
        Ok(())
    }

    /// internal
    fn calculate_signature(
        &mut self,
        header: &mut Header,
        raw_data: &Vec<u8>,
    ) -> Result<u128, Box<dyn Error>> {
        // Write header.
        let signture_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; Header::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signture_backup;
        self.signing_algo.start(&header);
        self.signing_algo.update(&header_bytes.into_inner());

        // And write rest of the raw message.
        let message_body = &raw_data[Header::STRUCT_SIZE..];
        self.signing_algo.update(message_body);

        Ok(self.signing_algo.finalize())
    }
}
