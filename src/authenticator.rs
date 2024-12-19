use std::error::Error;
use der::{asn1::OctetStringRef, Decode, Encode, oid::ObjectIdentifier};
use gss_api::negotiation::*;
use gss_api::InitialContextToken;
use sspi::{ntlm::NtlmConfig, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, ClientRequestFlags, CredentialUse, DataRepresentation, InitializeSecurityContextResult, Ntlm, OwnedSecurityBuffer, SecurityBuffer, SecurityBufferType, Sspi, SspiImpl};

pub struct GssAuthenticator {
    mech_types_data: Vec<u8>,
    server_accepted_auth_valid: bool,
    auth_session: Box<dyn GssAuthTokenHandler>,
}

const SPENGO_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2");
const NTLM_MECH_TYPE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10");

impl GssAuthenticator {
    pub fn build(token: &[u8], identity: AuthIdentity) -> Result<(GssAuthenticator, Vec<u8>), Box<dyn Error>> {
        let mut auth_session = Self::parse_inital_context_token(token, identity)?;
        let next_buffer = auth_session.next(None)?;
        
        // It is negTokenInit2 -- the first response.
        let token = NegTokenInit2 {
            mech_types: Some(vec![NTLM_MECH_TYPE_OID]),
            req_flags: None,
            neg_hints: None,
            mech_token: Some(OctetStringRef::new(&next_buffer)?),
            mech_list_mic: None
        };
        let mech_types_data = token.mech_types.to_der()?;
        let res = NegotiationToken::NegTokenInit2(token);

        Ok((GssAuthenticator {
            mech_types_data: mech_types_data,
            server_accepted_auth_valid: false,
            auth_session
        }, res.to_der()?))
    }

    fn parse_inital_context_token<'a>(token: &'a [u8], identity: AuthIdentity) -> Result<Box<dyn GssAuthTokenHandler>, Box<dyn Error>> {
        let token = InitialContextToken::from_der(&token)?;
        if token.this_mech != SPENGO_OID {
            return Err("Unexpected mechanism".into());
        }
        let der_of_inner = token.inner_context_token.to_der()?;
        let inner_spengo_val = NegotiationToken::from_der(&der_of_inner)?;
        let inner_spengo = match inner_spengo_val {
            NegotiationToken::NegTokenInit2(inner_spengo) => inner_spengo,
            _ => return Err("Unexpected token".into())
        };
        if inner_spengo.mech_types.ok_or("No mech types")?.iter().all(|oid| oid != &NTLM_MECH_TYPE_OID) {
            return Err("NTLM not in mech types".into());
        };

        Ok(Box::new(NtlmGssAuthSession::new(NtlmConfig::default(), identity)?))
    }

    pub fn next(&mut self, next_token: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        match self.auth_session.is_complete()? {
            true => {
                let mut mic_to_validate = Self::get_mic_from_complete(&next_token)?;
                self.auth_session.gss_validatemic(&mut mic_to_validate)?;
                Ok(vec![])
            },
            false => {
                let ntlm_token = Self::get_token_from_incomplete(&next_token)?;
                let out_token = self.auth_session.next(Some(ntlm_token))?;
        
                let mech_list_mic = self.auth_session.gss_getmic(&mut self.mech_types_data)?;
        
                let res = NegotiationToken::NegTokenResp(NegTokenResp {
                    mech_list_mic: Some(OctetStringRef::new(&mech_list_mic)?),
                    neg_state: None,
                    response_token: Some(OctetStringRef::new(&out_token)?),
                    supported_mech: Some(NTLM_MECH_TYPE_OID)
                });
                Ok(res.to_der()?)
            }
        }
    }

    pub fn is_authenticated(&self) -> Result<bool, Box<dyn Error>> {
        return self.auth_session.is_complete();
    }

    fn parse_response(token: &[u8]) -> Result<NegTokenResp, Box<dyn Error>> {
        let token = NegotiationToken::from_der(token)?;
        match token {
            NegotiationToken::NegTokenResp(token) => Ok(token),
            _ => Err("Unexpected token".into())
        }
    }

    fn get_token_from_incomplete(token: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let token = Self::parse_response(&token)?;

        if token.neg_state != Some(NegState::AcceptIncomplete) {
            return Err("Unexpected neg state".into());
        }
        if token.response_token.is_none() {
            return Err("No token value in response!".into());
        }
        let response_data = token.response_token
            .ok_or("No response in token buffer!")?
            .as_bytes().to_vec();
        Ok(response_data)
    }

    fn get_mic_from_complete(token: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let token = Self::parse_response(&token)?;

        if token.neg_state != Some(NegState::AcceptCompleted) {
            return Err("Unexpected neg state".into());
        }
        if token.mech_list_mic.is_none() {
            return Err("No MIC in response!".into());
        }
        let mic_data = token.mech_list_mic
            .ok_or("No MIC in token buffer!")?
            .as_bytes().to_vec();
        Ok(mic_data)
    }

}

pub trait GssAuthTokenHandler {
    fn next(&mut self, ntlm_token: Option<Vec<u8>>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn gss_getmic(&mut self, buffer: &mut Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>>;
    fn gss_validatemic(&mut self, buffer: &mut Vec<u8>) -> Result<(), Box<dyn Error>>;
    fn is_complete(&self) -> Result<bool, Box<dyn Error>>;
}

struct NtlmGssAuthSession {
    ntlm: Ntlm,
    identity: AuthIdentity,
    acq_cred_result: AcquireCredentialsHandleResult<Option<AuthIdentityBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,
    seq_num: u32,
}

impl NtlmGssAuthSession {
    pub fn new(ntlm_config: NtlmConfig, identity: AuthIdentity) -> Result<Self, Box<dyn Error>> {
        let mut ntlm = Ntlm::with_config(ntlm_config);
        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)?;
        Ok(Self {
            ntlm,
            identity,
            acq_cred_result,
            current_state: None,
            seq_num: 0
        })
    }
}

impl GssAuthTokenHandler for NtlmGssAuthSession {
    /// Process the next NTLM token from the server, and return the next token to send to the server.
    fn next(&mut self, ntlm_token: Option<Vec<u8>>) -> Result<Vec<u8>, Box<dyn Error>> {
        if self.current_state.is_some() && self.current_state.as_ref().unwrap().status != sspi::SecurityStatus::ContinueNeeded {
            return Err(format!("Unexpected state {:?} -- not ContinueNeeded!", self.current_state).into());
        }

        let mut output_buffer = vec![OwnedSecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut builder = self.ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.acq_cred_result.credentials_handle)
            .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY | ClientRequestFlags::INTEGRITY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(self.identity.username.account_name())
            .with_output(&mut output_buffer);

        let mut input_buffers = vec![];
        // let mut expected_next_state: SecurityStatus = sspi::SecurityStatus::ContinueNeeded;
        if let Some(ntlm_token) = ntlm_token {
            input_buffers.push(OwnedSecurityBuffer::new(ntlm_token, SecurityBufferType::Token));
            builder = builder.with_input(&mut input_buffers);
        }

        self.current_state = Some(self.ntlm
            .initialize_security_context_impl(&mut builder)?
            .resolve_to_result()?);
        
        return Ok(output_buffer.pop().unwrap().buffer);
    }

    fn is_complete(&self) -> Result<bool, Box<dyn Error>> {
        Ok(self.current_state.as_ref().ok_or("No last state set! Call next() to initialize properly.")?.status == sspi::SecurityStatus::Ok)
    }

    fn gss_getmic(&mut self, buffer: &mut Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let data_buffer = SecurityBuffer::with_security_buffer_type(SecurityBufferType::Data)?
            .with_data(buffer)?;
        let mut token_dest = vec![0; 16];
        let token_dest_buffer = SecurityBuffer::with_security_buffer_type(SecurityBufferType::Token)?
            .with_data(&mut token_dest)?;
        self.ntlm.sign_and_revert_state(&mut vec![data_buffer, token_dest_buffer], self.seq_num)?;
        self.seq_num += 1;
        Ok(token_dest)
    }

    fn gss_validatemic(&mut self, buffer: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        todo!()
    }

}
