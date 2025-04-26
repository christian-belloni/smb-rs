//! A basic create file test.

mod common;
use common::make_server_connection;
use serial_test::serial;
use smb::{packets::fscc::FileDispositionInformation, FileCreateArgs};

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_integration() -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, share_path) = make_server_connection("MyShare", None).await?;

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
