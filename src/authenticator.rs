use std::error::Error;
use der::{asn1::{ContextSpecific, OctetStringRef}, oid, Decode, DecodeValue, DerOrd, Encode, Header, TagNumber};
use gss_api;
use sspi::{AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, ClientRequestFlags, CredentialUse, DataRepresentation, InitializeSecurityContextResult, Ntlm, OwnedSecurityBuffer, Secret, SecurityBufferType, Sspi, SspiImpl, Username};

pub struct GssAuthenticator {
    ntlm: Ntlm,
    identity: AuthIdentity,
    acq_cred_result: AcquireCredentialsHandleResult<Option<AuthIdentityBuffers>>,
    current_state: Option<InitializeSecurityContextResult>
}

const SPENGO_OID: oid::ObjectIdentifier = oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2");
const NTLM_MECH_TYPE_OID: oid::ObjectIdentifier = oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10");

impl GssAuthenticator {
    pub fn build(token: &[u8], username: &String, password: String) -> Result<(GssAuthenticator, Vec<u8>), Box<dyn Error>> {
        let token = gss_api::InitialContextToken::from_der(&token)?;
        if token.this_mech != SPENGO_OID {
            return Err("Unexpected mechanism".into());
        }
        let inner_spengo_val = SpengoMechTypes::from_der(token.inner_context_token.value())?;
        if !inner_spengo_val.mech_types.iter().any(|oid| oid.der_cmp(&NTLM_MECH_TYPE_OID).unwrap().is_eq()) {
            return Err("No supported mehcanism provided (NTLM not specified!)".into());
        }
        let mut ntlm = Ntlm::new();
        let identity = AuthIdentity { 
            username: Username::new(username, None)?,
            password: Secret::new(password) 
        };
        let acq_cred_result = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)?;
        
        // Make sure the token is
        let mut authr = GssAuthenticator {
            ntlm,
            identity,
            acq_cred_result,
            current_state: None
        };
        let next_buffer = authr.next_buffer(None)?;
        Ok((authr, next_buffer))
    }

    pub fn next_buffer(&mut self, next_token: Option<Vec<u8>>) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut output_buffer = vec![OwnedSecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

        let mut builder = self.ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.acq_cred_result.credentials_handle)
            .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(self.identity.username.account_name())
            .with_output(&mut output_buffer);

        let mut input_buffers = vec![];
        if let Some(next_token) = next_token {
            let next_token = Self::unwrap_gss_token(&next_token)?;
            input_buffers.push(next_token);
            builder = builder.with_input(&mut input_buffers);
        }

        self.current_state = Some(self.ntlm
            .initialize_security_context_impl(&mut builder)?
            .resolve_to_result()?);
        
        // All the "next" buffers here should be negTokenTarg tokens.

        return Ok(Self::wrap_gss_token(&output_buffer)?);
    }

    pub fn is_complete(&self) -> bool {
        if let Some(state) = &self.current_state {
            state.status == sspi::SecurityStatus::CompleteAndContinue
        } else {
            false
        }
    }

    fn wrap_gss_token(token: &Vec<OwnedSecurityBuffer>) -> Result<Vec<u8>, Box<dyn Error>> {
        assert!(token.len() == 1);

        Ok(gss_api::negotiation::NegTokenResp {
            neg_state: Some(gss_api::negotiation::NegState::AcceptIncomplete),
            supported_mech: Some(NTLM_MECH_TYPE_OID),
            response_token: Some(OctetStringRef::new(&token[0].buffer)?),
            mech_list_mic: None
        }.to_der()?)
    }

    fn unwrap_gss_token(token: &[u8]) -> Result<OwnedSecurityBuffer, Box<dyn Error>> {
        let token = gss_api::negotiation::NegTokenResp::from_der(token)?;
        if token.neg_state != Some(gss_api::negotiation::NegState::AcceptIncomplete) {
            return Err("Unexpected neg state".into());
        }
        if token.supported_mech != Some(NTLM_MECH_TYPE_OID) {
            return Err("Unexpected mechanism".into());
        }
        if token.response_token.is_none() {
            return Err("No response token".into());
        }
        let response_data = token.response_token
            .ok_or("No response in token buffer!")?
            .as_bytes().to_vec();
        Ok(OwnedSecurityBuffer::new(response_data, SecurityBufferType::Token))
    }

}

#[derive(Debug, der::Sequence)]
struct SpengoMechTypes {
    #[asn1(context_specific = "0")]
    mech_types: Vec<oid::ObjectIdentifier>
}
