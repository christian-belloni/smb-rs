use smb::{
    packets::smb2::{CreateDisposition, FileAccessMask},
    Connection,
};
use std::env::var;

#[maybe_async::test(
    feature = "sync",
    async(feature = "async", tokio::test(flavor = "multi_thread"))
)]
pub async fn test_smb_integration_basic() -> Result<(), Box<dyn std::error::Error>> {
    use smb::packets::smb2::FileDispositionInformation;

    let mut smb = Connection::new();
    // Default to localhost, LocalAdmin, 123456
    let server = var("SMB_SERVER").unwrap_or("127.0.0.1:445".to_string());
    let user = var("SMB_USER").unwrap_or("LocalAdmin".to_string());
    let password = var("SMB_PASSWORD").unwrap_or("123456".to_string());
    // Connect & Authenticate
    smb.connect(&server).await?;
    let mut session = smb.authenticate(&user, password).await?;
    let mut tree = session.tree_connect("MyShare").await?;

    // Hello, World! > test.txt
    {
        let mut file = tree
            .create(
                "test.txt",
                CreateDisposition::Create,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            )
            .await?
            .unwrap_file();

        file.write(b"Hello, World!").await?;
    }

    {
        let file = tree
            .create(
                "test.txt",
                CreateDisposition::Open,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_delete(true),
            )
            .await?
            .unwrap_file();

        let mut buf = [0u8; 15];
        let read_length = file.read_block(&mut buf, 0).await?;
        assert_eq!(read_length, 13);
        assert_eq!(&buf[..13], b"Hello, World!");
        file.set_file_info(FileDispositionInformation {
            delete_pending: true.into(),
        })
        .await?;
    }

    Ok(())
}
