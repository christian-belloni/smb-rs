use sspi::{
    ntlm::NtlmConfig, AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags,
    CredentialUse, DataRepresentation, InitializeSecurityContextResult, Negotiate, SecurityBuffer,
    Sspi, SspiImpl,
};
use sspi::{CredentialsBuffers, NegotiateConfig};

use crate::Error;

#[derive(Debug)]
pub struct GssAuthenticator {
    auth_session: Box<dyn GssAuthTokenHandler>,
}

impl GssAuthenticator {
    pub fn build(
        token: &[u8],
        identity: AuthIdentity,
    ) -> crate::Result<(GssAuthenticator, Vec<u8>)> {
        let mut auth_session = Box::new(NtlmGssAuthSession::new(
            "aviv".to_string(), // TODO: Pull from config.
            identity,
        )?);
        let next_buffer = auth_session.next(Some(token.to_vec()))?;

        Ok((GssAuthenticator { auth_session }, next_buffer))
    }

    pub fn next(&mut self, next_token: &Vec<u8>) -> crate::Result<Option<Vec<u8>>> {
        if self.auth_session.is_complete()? {
            return Ok(None);
        }
        let out_token = self.auth_session.next(Some(next_token.clone()))?;
        Ok(Some(out_token))
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        return Ok(self.auth_session.is_complete()?);
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        self.auth_session.session_key()
    }
}

// TODO: Remove this trait, and embed the logic in the GssAuthenticator.
pub trait GssAuthTokenHandler: Send + Sync + std::fmt::Debug {
    fn next(&mut self, ntlm_token: Option<Vec<u8>>) -> crate::Result<Vec<u8>>;
    fn is_complete(&self) -> crate::Result<bool>;
    fn session_key(&self) -> crate::Result<[u8; 16]>;
}

#[derive(Debug)]
struct NtlmGssAuthSession {
    ntlm: Negotiate,
    cred_handle: AcquireCredentialsHandleResult<Option<CredentialsBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,
}

impl NtlmGssAuthSession {
    pub fn new(client_computer_name: String, identity: AuthIdentity) -> crate::Result<Self> {
        // kerberos get creds from SSPI_KDC_URL env var(s)
        let mut negotiate = Negotiate::new(NegotiateConfig {
            protocol_config: Box::new(NtlmConfig::default()),
            package_list: Some(String::from("kerberos,ntlm")),
            client_computer_name,
        })?;
        let cred_handle = negotiate
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity))
            .execute(&mut negotiate)
            .expect("Failed to acquire credentials handle");
        Ok(Self {
            ntlm: negotiate,
            cred_handle,
            current_state: None,
        })
    }

    fn make_sspi_target_name(server_fqdn: &str) -> String {
        format!("cifs/{}", server_fqdn)
    }

    // Those are exactly the flags provided to InitializeSecurityContextW
    // in mrxsmb20.sys - The windows SMB2/3 driver.
    fn get_context_requirements() -> ClientRequestFlags {
        ClientRequestFlags::DELEGATE
            | ClientRequestFlags::MUTUAL_AUTH
            | ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::FRAGMENT_TO_FIT
    }

    const SSPI_REQ_DATA_REPRESENTATION: DataRepresentation = DataRepresentation::Native;
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
        let target_name = Self::make_sspi_target_name("adc.aviv.local");
        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.cred_handle.credentials_handle)
            .with_context_requirements(Self::get_context_requirements())
            .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
            .with_target_name(&target_name)
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

    fn session_key(&self) -> crate::Result<[u8; 16]> {
        // Use the first 16 bytes of the session key.
        let k = &self.ntlm.query_context_session_key()?.session_key[..16];
        Ok(k.try_into().unwrap())
    }
}
