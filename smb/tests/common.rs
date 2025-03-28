use log::info;
use smb::{session::Session, tree::Tree, Connection, ConnectionConfig};
use std::env::var;

#[maybe_async::maybe_async]
pub async fn make_server_connection(
    share: &str,
    config: Option<ConnectionConfig>,
) -> Result<(Connection, Session, Tree), Box<dyn std::error::Error>> {
    let mut smb = Connection::build(config.unwrap_or(Default::default()))?;
    smb.set_timeout(std::time::Duration::from_secs(10)).await?;
    // Default to localhost, LocalAdmin, 123456
    let server = var("SMB_RUST_TESTS_SERVER").unwrap_or("127.0.0.1:445".to_string());
    let user = var("SMB_RUST_TESTS_USER_NAME").unwrap_or("LocalAdmin".to_string());
    let password = var("SMB_RUST_TESTS_PASSWORD").unwrap_or("123456".to_string());

    info!("Connecting to {} as {}", server, user);

    // Connect & Authenticate
    smb.connect(&server).await?;
    info!("Connected, authenticating...");
    let session = smb.authenticate(&user, password).await?;
    info!("Authenticated!");

    // String before ':', after is port:
    let server_name = server.split(':').next().unwrap();
    let tree = session
        .tree_connect(format!("\\\\{}\\{}", server_name, share).as_str())
        .await?;
    info!("Connected to share, start test basic");

    Ok((smb, session, tree))
}
