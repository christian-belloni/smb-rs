//! A basic create file test.

mod common;
use common::make_server_connection;
use serial_test::serial;
use smb::{packets::fscc::FileDispositionInformation, ConnectionConfig, FileCreateArgs};

#[maybe_async::maybe_async]
async fn do_test_basic_integration(
    conn_config: Option<ConnectionConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, share_path) = make_server_connection("MyShare", conn_config).await?;

    // Create a file
    let file = client
        .create_file(
            &share_path.with_path("basic.txt".to_string()),
            &FileCreateArgs::make_create_new(Default::default(), Default::default()),
        )
        .await?
        .unwrap_file();

    file.set_file_info(FileDispositionInformation::default())
        .await?;

    Ok(())
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_integration() -> Result<(), Box<dyn std::error::Error>> {
    do_test_basic_integration(None).await
}

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_netbios() -> Result<(), Box<dyn std::error::Error>> {
    use smb::connection::TransportConfig;

    let conn_config = ConnectionConfig {
        transport: TransportConfig::NetBios,
        ..Default::default()
    };
    do_test_basic_integration(Some(conn_config)).await
}
