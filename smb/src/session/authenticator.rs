use std::sync::Arc;

use sspi::{
    ntlm::NtlmConfig, AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags,
    CredentialUse, DataRepresentation, InitializeSecurityContextResult, Negotiate, SecurityBuffer,
    Sspi,
};
use sspi::{CredentialsBuffers, NegotiateConfig, SspiImpl};

use crate::connection::connection_info::ConnectionInfo;
use crate::connection::AuthMethodsConfig;
use crate::Error;

#[derive(Debug)]
pub struct Authenticator {
    server_hostname: String,

    ssp: Negotiate,
    cred_handle: AcquireCredentialsHandleResult<Option<CredentialsBuffers>>,
    current_state: Option<InitializeSecurityContextResult>,
}

pub enum AuthenticationStep {
    NextToken(Vec<u8>),
    Complete,
}

impl Authenticator {
    pub fn build(
        identity: AuthIdentity,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Authenticator> {
        let client_computer_name = conn_info
            .config
            .client_name
            .as_ref()
            .unwrap_or(&String::from("smb-rs"))
            .clone();
        let mut negotiate_ssp = Negotiate::new_client(NegotiateConfig::new(
            Box::new(NtlmConfig::default()),
            Some(Self::get_available_ssp_pkgs(&conn_info.config.auth_methods)),
            client_computer_name,
        ))?;
        let cred_handle = negotiate_ssp
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&sspi::Credentials::AuthIdentity(identity))
            .execute(&mut negotiate_ssp)?;

        Ok(Authenticator {
            server_hostname: conn_info.server.clone(),
            ssp: negotiate_ssp,
            cred_handle,
            current_state: None,
        })
    }

    pub fn is_authenticated(&self) -> crate::Result<bool> {
        if self.current_state.is_none() {
            return Ok(false);
        }
        Ok(self.current_state.as_ref().unwrap().status == sspi::SecurityStatus::Ok)
    }

    pub fn session_key(&self) -> crate::Result<[u8; 16]> {
        // Use the first 16 bytes of the session key.
        let key_info = self.ssp.query_context_session_key()?;
        let k = &key_info.session_key.as_ref()[..16];
        Ok(k.try_into().unwrap())
    }

    fn make_sspi_target_name(server_fqdn: &str) -> String {
        format!("cifs/{server_fqdn}")
    }

    fn get_context_requirements() -> ClientRequestFlags {
        ClientRequestFlags::DELEGATE
            | ClientRequestFlags::MUTUAL_AUTH
            | ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::FRAGMENT_TO_FIT
            | ClientRequestFlags::USE_SESSION_KEY
    }

    const SSPI_REQ_DATA_REPRESENTATION: DataRepresentation = DataRepresentation::Native;

    pub fn next(&mut self, gss_token: &[u8]) -> crate::Result<AuthenticationStep> {
        if self.is_authenticated()? {
            return Ok(AuthenticationStep::Complete);
        }

        if self.current_state.is_some()
            && self.current_state.as_ref().unwrap().status != sspi::SecurityStatus::ContinueNeeded
        {
            return Err(Error::InvalidState(
                "NTLM GSS session is not in a state to process next token.".into(),
            ));
        }

        let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let target_name = Self::make_sspi_target_name(&self.server_hostname);
        let mut builder = self
            .ssp
            .initialize_security_context()
            .with_credentials_handle(&mut self.cred_handle.credentials_handle)
            .with_context_requirements(Self::get_context_requirements())
            .with_target_data_representation(Self::SSPI_REQ_DATA_REPRESENTATION)
            .with_output(&mut output_buffer);

        if cfg!(feature = "kerberos") {
            builder = builder.with_target_name(&target_name)
        }

        let mut input_buffers = vec![];
        input_buffers.push(SecurityBuffer::new(gss_token.to_owned(), BufferType::Token));
        builder = builder.with_input(&mut input_buffers);

        let result = {
            let mut generator = self.ssp.initialize_security_context_impl(&mut builder)?;
            // Kerberos requires a network client to be set up.
            // We avoid compiling with the network client if kerberos is not enabled,
            // so be sure to avoid using it in that case.
            #[cfg(feature = "kerberos")]
            {
                generator.resolve_with_default_network_client()?
            }
            #[cfg(not(feature = "kerberos"))]
            {
                generator.resolve_to_result()?
            }
        };

        self.current_state = Some(result);

        Ok(AuthenticationStep::NextToken(
            output_buffer
                .pop()
                .ok_or(Error::InvalidState(
                    "SSPI output buffer is empty.".to_string(),
                ))?
                .buffer,
        ))
    }

    fn get_available_ssp_pkgs(config: &AuthMethodsConfig) -> String {
        let krb_pku2u_config = if cfg!(feature = "kerberos") && config.kerberos {
            "kerberos,!pku2u"
        } else {
            "!kerberos,!pku2u"
        };
        let ntlm_config = if config.ntlm { "ntlm" } else { "!ntlm" };
        format!("{ntlm_config},{krb_pku2u_config}")
    }
}
