use crate::{copy::CopyCmd, info::InfoCmd};
use clap::{Parser, Subcommand};
use smb::{
    connection::{
        AuthMethodsConfig, EncryptionMode, QuicCertValidationOptions, QuicConfig, TransportConfig,
    },
    packets::smb2::Dialect,
    ClientConfig, ConnectionConfig,
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(short, long)]
    pub timeout: Option<u16>,

    #[arg(long)]
    pub negotiate_smb2_only: bool,
    #[arg(long)]
    pub no_dfs: bool,

    /// Disables NTLM authentication.
    #[arg(long)]
    pub no_ntlm: bool,
    /// Disables Kerberos authentication.
    #[arg(long)]
    pub no_kerberos: bool,

    #[arg(long)]
    pub quic_transport: bool,

    #[arg(short, long)]
    pub username: String,
    #[arg(short, long)]
    pub password: String,

    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn make_smb_client_config(&self) -> ClientConfig {
        ClientConfig {
            dfs: !self.no_dfs,
            connection: ConnectionConfig {
                max_dialect: Some(Dialect::MAX),
                encryption_mode: EncryptionMode::Allowed,
                timeout: self
                    .timeout
                    .map(|t| std::time::Duration::from_secs(t.into())),
                smb2_only_negotiate: self.negotiate_smb2_only,
                transport: if self.quic_transport {
                    TransportConfig::Quic(QuicConfig {
                        local_address: None,
                        cert_validation: QuicCertValidationOptions::PlatformVerifier,
                    })
                } else {
                    TransportConfig::Tcp
                },
                port: self.port,
                auth_methods: AuthMethodsConfig {
                    ntlm: !self.no_ntlm,
                    kerberos: !self.no_kerberos,
                },
                ..Default::default()
            },
        }
    }
}

#[derive(Subcommand)]
pub enum Commands {
    Copy(CopyCmd),
    Info(InfoCmd),
}
