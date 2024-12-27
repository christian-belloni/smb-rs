use binrw::prelude::*;
use std::{error::Error, cell::RefCell, io::Cursor};

use crate::{
    msg_handler::{IncomingSMBMessage, OutgoingSMBMessage, SMBMessageHandler},
    packets::{
        netbios::NetBiosTcpMessage,
        smb2::{
            header::{SMB2MessageHeader, SMB2Status}, message::{SMB2Message, SMBMessageContent}, negotiate::SigningAlgorithmId, tree::SMB2TreeConnectRequest,
        },
    },
    smb_crypto::{SMBCrypto, SMBSigningAlgo},
    smb_tree::SMBTree,
};

pub struct SMBSession<'a> {
    session_id: u64,
    signing_key: Option<[u8; 16]>,

    upstream: RefCell<&'a dyn SMBMessageHandler>,
}

impl SMBSession<'_> {
    pub fn new<'a>(session_id: u64, upstream: RefCell<&'a dyn SMBMessageHandler>) -> SMBSession {
        SMBSession {
            session_id,
            signing_key: None,
            upstream
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn setup(
        &mut self,
        exchanged_session_key: &Vec<u8>,
        preauth_integrity_hash: [u8; 64],
    ) -> Result<(), Box<dyn Error>> {
        self.signing_key = Some(Self::derive_signing_key(
            exchanged_session_key,
            preauth_integrity_hash,
        )?);
        Ok(())
    }

    pub fn is_set_up(&self) -> bool {
        self.signing_key.is_some()
    }

    fn make_signer(&self) -> Result<SMBSigner, Box<dyn Error>> {

        if self.is_set_up() {
            debug_assert!(self.signing_key.is_some());
            return Err("Signing key is not set -- you must succeed a setup() to continue.".into());
        }

        Ok(SMBSigner::new(SMBCrypto::make_signing_algo(
            SigningAlgorithmId::AesCmac,
            self.signing_key.as_ref().unwrap(),
        ).unwrap()))
    }

    fn derive_signing_key(
        exchanged_session_key: &Vec<u8>,
        preauth_integrity_hash: [u8; 64],
    ) -> Result<[u8; 16], Box<dyn Error>> {
        assert!(exchanged_session_key.len() == 16);

        let mut session_key = [0; 16];
        session_key.copy_from_slice(&exchanged_session_key[0..16]);
        Ok(SMBCrypto::kbkdf_hmacsha256(
            &session_key,
            b"SMBSigningKey\x00",
            &preauth_integrity_hash,
        )?
        .try_into()
        .unwrap())
    }

    pub fn signing_enabled(&self) -> bool {
        true
    }

    pub fn tree_connect(&mut self, name: String) -> Result<SMBTree, Box<dyn Error>> {
        self.send(OutgoingSMBMessage::new(
            SMB2Message::new(SMBMessageContent::SMBTreeConnectRequest(SMB2TreeConnectRequest::new(name)))
        ))?;
        let response = self.receive()?;

        let _response = match response.message.content {
            SMBMessageContent::SMBTreeConnectResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();

        Ok(SMBTree::new(response.message.header.tree_id))
    }
}

impl SMBMessageHandler for SMBSession<'_> {
    fn send(&mut self, mut msg: OutgoingSMBMessage) -> Result<(), Box<dyn std::error::Error>> {
        // Set signing configuration. Upstream handler shall take care of the rest.
        if self.signing_enabled() && self.is_set_up() {
            msg.signer = Some(self.make_signer()?);
        }
        msg.message.header.session_id = self.session_id;
        let mut dm = (&mut *self.upstream.borrow_mut()).send(msg)?;
        Ok(())
    }

    fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        let mut incoming = self.upstream.borrow().receive()?;
        // TODO: check whether this is the correct case to do such a thing.
        if self.signing_enabled() && self.is_set_up() {
            // Skip authentication is message ID is -1 or status is pending.
            if incoming.message.header.message_id != u64::MAX && incoming.message.header.status != SMB2Status::StatusPending as u32 {
                self.make_signer()?.verify_signature(&mut incoming.message.header, &incoming.raw)?;
            }
        };
        Ok(incoming)
    }
}

#[derive(Debug)]
pub struct SMBSigner {
    signing_algo: Box<dyn SMBSigningAlgo>,
}

impl SMBSigner {
    pub fn new(signing_algo: Box<dyn SMBSigningAlgo>) -> SMBSigner {
        SMBSigner { signing_algo }
    }

    pub fn verify_signature(
        &mut self,
        header: &mut SMB2MessageHeader,
        raw_data: &NetBiosTcpMessage,
    ) -> Result<(), Box<dyn Error>> {
        let calculated_signature = self.calculate_signature(header, raw_data)?;
        if calculated_signature != header.signature {
            return Err("Signature verification failed".into());
        }
        Ok(())
    }

    pub fn sign_message(
        &mut self,
        header: &mut SMB2MessageHeader,
        raw_data: &mut NetBiosTcpMessage,
    ) -> Result<(), Box<dyn Error>> {
        header.signature = self.calculate_signature(header, raw_data)?;
        // Update raw data to include the signature.
        let mut header_writer =
            Cursor::new(&mut raw_data.content[0..SMB2MessageHeader::STRUCT_SIZE]);
        header.write(&mut header_writer)?;
        Ok(())
    }

    fn calculate_signature(
        &mut self,
        header: &mut SMB2MessageHeader,
        raw_message: &NetBiosTcpMessage,
    ) -> Result<u128, Box<dyn Error>> {
        // Write header.
        let signture_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; SMB2MessageHeader::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signture_backup;
        self.signing_algo.update(&header_bytes.into_inner());

        // And write rest of the raw message.
        let message_body = &raw_message.content[SMB2MessageHeader::STRUCT_SIZE..];
        self.signing_algo.update(message_body);

        Ok(self.signing_algo.finalize())
    }

}