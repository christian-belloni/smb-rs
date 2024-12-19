use std::error::Error;
use der::{asn1::{ContextSpecific, OctetStringRef}, oid, Decode, DecodeValue, DerOrd, Encode, Header, TagNumber};
use gss_api::negotiation::*;
use gss_api::InitialContextToken;
use sspi::{ntlm::NtlmConfig, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, ClientRequestFlags, CredentialUse, DataRepresentation, EncryptionFlags, InitializeSecurityContextResult, Ntlm, OwnedSecurityBuffer, Secret, SecurityBuffer, SecurityBufferType, SecurityStatus, Sspi, SspiImpl, Username};

pub struct GssAuthenticator {
    ntlm: Ntlm,
    identity: AuthIdentity,
    acq_cred_result: AcquireCredentialsHandleResult<Option<AuthIdentityBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,
    mech_types_data: Vec<u8>
}

const SPENGO_OID: oid::ObjectIdentifier = oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.2");
const NTLM_MECH_TYPE_OID: oid::ObjectIdentifier = oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.2.10");

impl GssAuthenticator {
    pub fn build(token: &[u8], username: &String, password: String) -> Result<(GssAuthenticator, Vec<u8>), Box<dyn Error>> {
        let token = InitialContextToken::from_der(&token)?;
        if token.this_mech != SPENGO_OID {
            return Err("Unexpected mechanism".into());
        }
        let der_of_inner = token.inner_context_token.to_der()?;
        let inner_spengo_val = NegotiationToken::from_der(&der_of_inner)?;
        let inner_spengo = match inner_spengo_val {
            NegotiationToken::NegTokenInit2(inner_spengo) => inner_spengo,
            _ => return Err("Unexpected token".into())
        };// TODO: Assert NTLM in mech_types!

        let mut ntlm = Ntlm::with_config(NtlmConfig::new("MACBOOKPRO-AF8A".to_string()));
        let identity = AuthIdentity { 
            username: Username::new(username, Some("AVIVVM"))?,
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
            current_state: None,
            mech_types_data: vec![]
        };
        let next_buffer = authr.next_buffer(None)?;
        
        // It is negTokenInit:
        let token = NegTokenInit2 {
            mech_types: Some(vec![NTLM_MECH_TYPE_OID]),
            req_flags: None,
            neg_hints: None,
            mech_token: Some(OctetStringRef::new(&next_buffer[0].buffer)?),
            mech_list_mic: None
        };
        let mech_types_data = token.mech_types.to_der()?;
        dbg!(&mech_types_data);
        authr.mech_types_data = mech_types_data;

        let res = NegotiationToken::NegTokenInit2(token);

        Ok((authr, res.to_der()?))
    }

    pub fn next(&mut self, next_token: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let out_token = self.next_buffer(Some(next_token))?;
        assert!(out_token.len() == 1);
        // assert!(self.current_state.as_ref().unwrap().status == sspi::SecurityStatus::ContinueNeeded);
        let mut token = [0; 128];
        let mut mech_types_data_clone = self.mech_types_data.clone();
        dbg!(&mech_types_data_clone);
        let mut buffer_of_mech_types = vec![SecurityBuffer::Data(&mut mech_types_data_clone), 
                                                                    SecurityBuffer::Token(&mut token)];
                                                                    println!("About to sign");
        let mechTypesMicOk = self.ntlm.sign_and_revert_state(&mut buffer_of_mech_types, 0)?;
        let res = NegotiationToken::NegTokenResp(NegTokenResp {
            mech_list_mic: Some(OctetStringRef::new(&token[..16])?),
            neg_state: None,
            response_token: Some(OctetStringRef::new(&out_token[0].buffer)?),
            supported_mech: Some(NTLM_MECH_TYPE_OID)
        });
        Ok(res.to_der()?)
    }

    fn next_buffer(&mut self, next_token: Option<Vec<u8>>) -> Result<Vec<OwnedSecurityBuffer>, Box<dyn Error>> {
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
        if let Some(next_token) = next_token {
            let (next_token, neg_state) = Self::unwrap_gss_token(&next_token)?;

            input_buffers.push(next_token);
            builder = builder.with_input(&mut input_buffers);

            // if neg_state == NegState::AcceptCompleted {
            //     expected_next_state = SecurityStatus::Ok;
            // }
        }

        self.current_state = Some(self.ntlm
            .initialize_security_context_impl(&mut builder)?
            .resolve_to_result()?);

        dbg!(&self.current_state);
        dbg!(&self.ntlm);
        
        // All the "next" buffers here should be negTokenTarg tokens.
        // dbg!(&output_buffer);
        // if self.current_state.as_ref().unwrap().status != expected_next_state {
        //     return Err(format!("Unexpected state during authentication -- {:?} not {expected_next_state:?}", self.current_state).into());
        // }

        return Ok(output_buffer);
    }

    pub fn is_complete(&self) -> bool {
        if let Some(state) = &self.current_state {
            state.status == sspi::SecurityStatus::CompleteAndContinue
        } else {
            false
        }
    }

    fn unwrap_gss_token(token: &[u8]) -> Result<(OwnedSecurityBuffer, NegState), Box<dyn Error>> {
        let token = NegotiationToken::from_der(token)?;
        // token should be response, if not, error:
        let token = match token {
            NegotiationToken::NegTokenResp(token) => token,
            _ => return Err("Unexpected token".into())
        };
        if token.neg_state != Some(NegState::AcceptIncomplete) && token.neg_state != Some(NegState::AcceptCompleted) {
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
        Ok((OwnedSecurityBuffer::new(response_data, SecurityBufferType::Token), token.neg_state.unwrap()))
    }

}

#[derive(Debug, der::Sequence)]
struct SpengoMechTypes {
    #[asn1(context_specific = "0")]
    mech_types: Vec<oid::ObjectIdentifier>
}
