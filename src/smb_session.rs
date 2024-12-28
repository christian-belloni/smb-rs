use binrw::prelude::*;
use sspi::{AuthIdentity, Secret, Username};
use std::{cell::OnceCell, error::Error, io::Cursor};

use crate::{
    authenticator::GssAuthenticator, msg_handler::{IncomingSMBMessage, OutgoingSMBMessage, SMBHandlerReference, SMBMessageHandler, SendMessageResult}, packets::{
        netbios::NetBiosTcpMessage,
        smb2::{
            header::{SMB2MessageHeader, SMB2Status}, message::{SMB2Message, SMBMessageContent}, negotiate::SigningAlgorithmId, session::SMB2SessionSetupRequest, tree::SMB2TreeConnectRequest
        },
    }, smb_client::SMBClientMessageHandler, smb_crypto::{SMBCrypto, SMBSigningAlgo}, smb_tree::SMBTree
};

pub struct SMBSession {
    session_id: OnceCell<u64>,
    signing_key: Option<[u8; 16]>,

    upstream: SMBHandlerReference<SMBClientMessageHandler>
}

impl SMBSession {
    pub fn new(upstream: SMBHandlerReference<SMBClientMessageHandler>) -> SMBSession {
        SMBSession {
            session_id: OnceCell::default(),
            signing_key: None,
            upstream
        }
    }

    pub fn setup(&mut self, user_name: String, password: String) -> Result<(), Box<dyn Error>> {

        // Build the authenticator.
        let (mut authenticator, next_buf) = {
            let handler = self
                .upstream
                .borrow();
            let negotate_state = handler
                .negotiate_state()
                .unwrap();
            let identity = AuthIdentity {
                username: Username::new(&user_name, Some("WORKGROUP"))?,
                password: Secret::new(password),
            };
            GssAuthenticator::build(negotate_state.get_gss_token(), identity)?
        };

        let request = OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(next_buf)),
        ));
        self.send(request)?;
        // response hash is processed later, in the loop.
        let response = self.receive()?;
        if response.message.header.status != SMB2Status::MoreProcessingRequired as u32 {
            return Err("Expected STATUS_MORE_PROCESSING_REQUIRED".into());
        }

        // Set session id.
        self.session_id.set(response.message.header.session_id).map_err(|_| "Session ID already set!")?;

        let mut response = Some(response);
        while !authenticator.is_authenticated()? {
            // If there's a response to process, do so.
            let last_setup_response = match response.as_ref() {
                Some(response) => Some(
                    match &response.message.content {
                        SMBMessageContent::SMBSessionSetupResponse(response) => Some(response),
                        _ => None,
                    }
                    .unwrap(),
                ),
                None => None,
            };

            let next_buf = match last_setup_response.as_ref() {
                Some(response) => authenticator.next(&response.buffer)?,
                None => authenticator.next(&vec![])?,
            };

            response = match next_buf {
                Some(next_buf) => {
                    // We'd like to update preauth hash with the last request before accept.
                    // therefore we update it here for the PREVIOUS repsponse, assuming that we get an empty request when done.
                    let mut request = OutgoingSMBMessage::new(SMB2Message::new(
                        SMBMessageContent::SMBSessionSetupRequest(SMB2SessionSetupRequest::new(
                            next_buf,
                        )),
                    ));
                    request.finalize_preauth_hash = true;
                    self.send(request)?;

                    // Keys exchanged? We can set-up the session!
                    if authenticator.keys_exchanged() && !self.is_set_up() {
                        // Derive keys and set-up the final session.
                        let ntlm_key = authenticator.session_key()?.to_vec();
                        // Lock preauth hash, we're done with it.
                        let hash = self.upstream.borrow_mut().finalize_preauth_hash();
                        // Derive signing key, and set-up the session.
                        self.key_setup(&ntlm_key, hash)?;
                    }

                    let response = self.receive()?;

                    Some(response)
                }
                None => None,
            };
        };
        Ok(())
    }

    pub fn session_id(&self) -> u64 {
        // TODO: w/ Error flow.
        *self.session_id.get().unwrap()
    }

    pub fn key_setup(
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

impl SMBMessageHandler for SMBSession {
    fn send(&mut self, mut msg: OutgoingSMBMessage) -> Result<SendMessageResult, Box<(dyn std::error::Error + 'static)>> {
        // Set signing configuration. Upstream handler shall take care of the rest.
        if self.signing_enabled() && self.is_set_up() {
            msg.message.header.flags.set_signed(true);
            msg.signer = Some(self.make_signer()?);
        }
        msg.message.header.session_id = *self.session_id.get().or(Some(&0)).unwrap();
        self.upstream.borrow_mut().send(msg)
    }

    fn receive(&mut self) -> Result<IncomingSMBMessage, Box<dyn std::error::Error>> {
        let mut incoming = self.upstream.borrow_mut().receive()?;
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