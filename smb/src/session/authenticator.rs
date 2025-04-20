use der::AnyRef;
use der::{asn1::OctetStringRef, oid::ObjectIdentifier, Decode, Encode};
use gss_api::negotiation::*;
use gss_api::InitialContextToken;
use sspi::{
    ntlm::NtlmConfig, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    BufferType, ClientRequestFlags, CredentialUse, DataRepresentation,
    InitializeSecurityContextResult, Kerberos, Negotiate, Ntlm, SecurityBuffer, SecurityBufferRef,
    Sspi, SspiImpl,
};
use sspi::{CredentialsBuffers, KerberosConfig, NegotiateConfig};
use url::Url;

use crate::Error;

#[derive(Debug)]
pub struct GssAuthenticator {
    // mech_types_data_sent: Vec<u8>,
    server_accepted_auth_valid: bool,
    auth_session: Box<dyn GssAuthTokenHandler>,
}

const SPENGO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2");
const NTLM_MECH_TYPE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10");
const MS_KRB5_MECH_TYPE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.48018.1.2.2");
// const KRB5_MECH_TYPE_OID: ObjectIdentifier =
//     ObjectIdentifier::new_unwrap("1.2.840.113554.1.2.2");

impl GssAuthenticator {
    pub fn build(
        token: &[u8],
        identity: AuthIdentity,
    ) -> crate::Result<(GssAuthenticator, Vec<u8>)> {
        let mut auth_session = Self::parse_inital_context_token(token, identity)?;
        let next_buffer = auth_session.next(Some(token.to_vec()))?;

        // // It is negTokenInit2 -- the first response.
        // let token = NegTokenInit2 {
        //     mech_types: Some(vec![MS_KRB5_MECH_TYPE_OID]),
        //     req_flags: None,
        //     neg_hints: None,
        //     mech_token: Some(OctetStringRef::new(&next_buffer)?),
        //     mech_list_mic: None,
        // };
        // let mech_types_data_sent = token.mech_types.to_der()?;
        // let res_mech = NegotiationToken::NegTokenInit2(token);
        // let inner_as_bytes = res_mech.to_der()?;
        // let res = InitialContextToken {
        //     this_mech: SPENGO_OID,
        //     inner_context_token: AnyRef::from_der(&inner_as_bytes)?,
        // };

        Ok((
            GssAuthenticator {
                // mech_types_data_sent,
                server_accepted_auth_valid: false,
                auth_session,
            },
            next_buffer,
        ))
    }

    fn parse_inital_context_token<'a>(
        token: &'a [u8],
        identity: AuthIdentity,
    ) -> crate::Result<Box<dyn GssAuthTokenHandler>> {
        let token = InitialContextToken::from_der(&token)?;
        if token.this_mech != SPENGO_OID {
            return Err(Error::UnsupportedAuthenticationMechanism(
                token.this_mech.to_string(),
            ));
        }
        let der_of_inner = token.inner_context_token.to_der()?;
        let inner_spengo_val = NegotiationToken::from_der(&der_of_inner)?;
        let inner_spengo = match inner_spengo_val {
            NegotiationToken::NegTokenInit2(inner_spengo) => inner_spengo,
            _ => return Err(Error::InvalidMessage("Unexpected negotiation token".into())),
        };
        if inner_spengo
            .mech_types
            .ok_or(Error::InvalidMessage(
                "No mech types in negotiation token!".into(),
            ))?
            .iter()
            .all(|oid| oid != &MS_KRB5_MECH_TYPE_OID)
        {
            return Err(Error::UnsupportedAuthenticationMechanism(
                "No NTLM mech type in negotiation token!".into(),
            ));
        };

        Ok(Box::new(NtlmGssAuthSession::new(
            NtlmConfig::default(),
            identity,
        )?))
    }

    pub fn next(&mut self, next_token: &Vec<u8>) -> crate::Result<Option<Vec<u8>>> {
        match self.auth_session.is_complete()? {
            true => {
                let mut mic_to_validate = Self::get_mic_from_complete(next_token)?;
                // self.auth_session
                //     .gss_validatemic(&mut self.mech_types_data_sent, &mut mic_to_validate)?;
                self.server_accepted_auth_valid = true;
                Ok(None)
            }
            false => {
                // let ntlm_token = Self::get_token_from_incomplete(next_token)?;
                let out_token = self.auth_session.next(Some(next_token.clone()))?;

                // let mech_list_mic = self
                //     .auth_session
                //     .gss_getmic(&mut self.mech_types_data_sent)?;

                // let res = NegotiationToken::NegTokenResp(NegTokenResp {
                //     mech_list_mic: Some(OctetStringRef::new(&mech_list_mic)?),
                //     neg_state: None,
                //     response_token: Some(OctetStringRef::new(&out_token)?),
                //     supported_mech: Some(MS_KRB5_MECH_TYPE_OID),
                // });
                Ok(Some(out_token))
            }
        }
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        return Ok(self.auth_session.is_complete()?);
    }

    fn parse_response(token: &[u8]) -> crate::Result<NegTokenResp> {
        let token = NegotiationToken::from_der(token)?;
        match token {
            NegotiationToken::NegTokenResp(token) => Ok(token),
            _ => Err(Error::InvalidMessage("Unexpected negotiation token".into())),
        }
    }

    fn get_token_from_incomplete(token: &[u8]) -> crate::Result<Vec<u8>> {
        let token = Self::parse_response(&token)?;

        if token.neg_state != Some(NegState::AcceptIncomplete) {
            return Err(Error::InvalidMessage(
                "Unexpected neg state in response!".into(),
            ));
        }

        let response_data = token
            .response_token
            .ok_or(Error::InvalidMessage(
                "No response in negotiation token!".into(),
            ))?
            .as_bytes()
            .to_vec();
        Ok(response_data)
    }

    fn get_mic_from_complete(token: &[u8]) -> crate::Result<Vec<u8>> {
        let token = Self::parse_response(&token)?;

        if token.neg_state != Some(NegState::AcceptCompleted) {
            return Err(Error::InvalidMessage(
                "Unexpected neg state in response!".into(),
            ));
        }

        let mic_data = token
            .mech_list_mic
            .ok_or(Error::InvalidMessage("No MIC in response!".into()))?
            .as_bytes()
            .to_vec();
        Ok(mic_data)
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        self.auth_session.session_key()
    }

    pub fn keys_exchanged(&self) -> bool {
        self.auth_session.session_key().is_ok()
    }
}

pub trait GssAuthTokenHandler: Send + Sync + std::fmt::Debug {
    fn next(&mut self, ntlm_token: Option<Vec<u8>>) -> crate::Result<Vec<u8>>;
    fn gss_getmic(&mut self, buffer: &mut [u8]) -> crate::Result<Vec<u8>>;
    fn gss_validatemic(&mut self, buffer: &mut [u8], signature: &mut [u8]) -> crate::Result<()>;
    fn is_complete(&self) -> crate::Result<bool>;
    fn session_key(&self) -> crate::Result<[u8; 16]>;
}

#[derive(Debug)]
struct NtlmGssAuthSession {
    ntlm: Negotiate,
    account_name: String,
    acq_cred_result: AcquireCredentialsHandleResult<Option<CredentialsBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,
    seq_num: u32,
}

impl NtlmGssAuthSession {
    pub fn new(ntlm_config: NtlmConfig, identity: AuthIdentity) -> crate::Result<Self> {
        let mut negotiate = Negotiate::new(NegotiateConfig {
            protocol_config: Box::new(KerberosConfig {
                kdc_url: Some(Url::parse("tcp://adc.aviv.local:88")?),
                client_computer_name: Some("aviv".to_string()),
            }),
            package_list: Some(String::from("kerberos,ntlm")),
            client_computer_name: "aviv".to_string(),
        })?;
        let account_name = identity.username.account_name().to_string();
        let acq_cred_result = negotiate
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity))
            .execute(&mut negotiate)
            .expect("Failed to acquire credentials handle");
        Ok(Self {
            ntlm: negotiate,
            account_name,
            acq_cred_result,
            current_state: None,
            seq_num: 0,
        })
    }
}

impl GssAuthTokenHandler for NtlmGssAuthSession {
    /// Process the next NTLM token from the server, and return the next token to send to the server.
    fn next(&mut self, ntlm_token: Option<Vec<u8>>) -> crate::Result<Vec<u8>> {
        if self.current_state.is_some()
            && self.current_state.as_ref().unwrap().status != sspi::SecurityStatus::ContinueNeeded
        {
            return Err(Error::InvalidState(
                "NTLM GSS session is not in a state to process next token.".into(),
            ));
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.acq_cred_result.credentials_handle)
            // Those are exactly the flags provided to InitializeSecurityContextW in mrxsmb20.sys - The windows
            // kernel driver for SMB2/3.
            .with_context_requirements(
                ClientRequestFlags::DELEGATE
                    | ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::FRAGMENT_TO_FIT,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("cifs/adc.aviv.local")
            .with_output(&mut output_buffer);

        let mut input_buffers = vec![];
        // let mut expected_next_state: SecurityStatus = sspi::SecurityStatus::ContinueNeeded;
        if let Some(ntlm_token) = ntlm_token {
            input_buffers.push(SecurityBuffer::new(ntlm_token, BufferType::Token));
            builder = builder.with_input(&mut input_buffers);
        }

        self.current_state = Some(
            self.ntlm
                .initialize_security_context_impl(&mut builder)?
                .resolve_with_default_network_client()?,
        );

        return Ok(output_buffer.pop().unwrap().buffer);
    }

    fn is_complete(&self) -> crate::Result<bool> {
        Ok(self
            .current_state
            .as_ref()
            .ok_or(Error::InvalidState("No current state is set!".into()))?
            .status
            == sspi::SecurityStatus::Ok)
    }

    fn gss_getmic(&mut self, buffer: &mut [u8]) -> crate::Result<Vec<u8>> {
        let data_buffer = SecurityBufferRef::data_buf(buffer);
        let mut signature = vec![0u8; 16];
        let token_dest_buffer = SecurityBufferRef::token_buf(&mut signature);
        let mut ntlm_copy = self.ntlm.clone();
        ntlm_copy.make_signature(0, &mut [data_buffer, token_dest_buffer], self.seq_num)?;
        Ok(signature)
    }

    fn gss_validatemic(&mut self, buffer: &mut [u8], signature: &mut [u8]) -> crate::Result<()> {
        let data_buffer = SecurityBufferRef::data_buf(buffer);
        let signature_buffer = SecurityBufferRef::token_buf(signature);

        // Avoid changing the state of the session when validating gss initial mic.
        self.ntlm
            .clone()
            .verify_signature(&mut [data_buffer, signature_buffer], self.seq_num)?;
        Ok(())
    }

    fn session_key(&self) -> crate::Result<[u8; 16]> {
        // Use the first 16 bytes of the session key.
        let k = &dbg!(self.ntlm.query_context_session_key()?.session_key)[..16];
        Ok(k.try_into().unwrap())
    }
}
