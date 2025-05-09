use smb::{Client, ClientConfig, ConnectionConfig, UncPath};
use std::env::var;

/// Creates a new SMB client and connects to the specified share on the server.
/// Returns the client and the UNC path used for the connection's share.
#[maybe_async::maybe_async]
pub async fn make_server_connection(
    share: &str,
    config: Option<ConnectionConfig>,
) -> Result<(Client, UncPath), Box<dyn std::error::Error>> {
    let server = var("SMB_RUST_TESTS_SERVER").unwrap_or("127.0.0.1".to_string());
    let user = var("SMB_RUST_TESTS_USER_NAME").unwrap_or("LocalAdmin".to_string());
    let password = var("SMB_RUST_TESTS_PASSWORD").unwrap_or("123456".to_string());

    let mut conn_config = config.unwrap_or(ConnectionConfig::default());
    conn_config.timeout = Some(std::time::Duration::from_secs(10));
    conn_config.auth_methods.kerberos = false;
    conn_config.auth_methods.ntlm = true;

    let mut smb = Client::new(ClientConfig {
        connection: conn_config,
        ..Default::default()
    });
    log::info!("Connecting to {}", server);

    let unc_path = UncPath {
        server: server.clone(),
        share: Some(share.to_string()),
        path: None,
    };
    // Connect & Authenticate
    smb.share_connect(&unc_path, user.as_str(), password.clone())
        .await?;

    log::info!("Connected to {}", unc_path);
    Ok((smb, unc_path))
}
