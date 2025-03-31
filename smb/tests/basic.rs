//! A basic create file test.

mod common;
use common::make_server_connection;
use serial_test::serial;
use smb::packets::fscc::FileDispositionInformation;

#[test_log::test(maybe_async::test(
    feature = "sync",
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_basic_integration() -> Result<(), Box<dyn std::error::Error>> {
    use smb::packets::{fscc::FileAccessMask, smb2::CreateDisposition};

    let (_smb, _session, tree) = make_server_connection("MyShare", None).await?;

    // Create a file
    let file = tree
        .create_file(
            "basic.txt",
            CreateDisposition::Create,
            FileAccessMask::new().with_generic_all(true),
        )
        .await?
        .unwrap_file();

    file.set_file_info(FileDispositionInformation::default())
        .await?;

    Ok(())
}
