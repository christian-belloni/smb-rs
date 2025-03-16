use log::info;
use serial_test::serial;
use smb::{
    connection::EncryptionMode,
    packets::{
        fscc::*,
        smb2::{CreateDisposition, Dialect},
    },
    Connection, ConnectionConfig,
};
use std::env::var;

macro_rules! basic_test {
    ([$dialect:ident], [$($encrypt_mode:ident),*]) => {
        $(
            paste::paste! {
                #[maybe_async::test(
                    feature = "sync",
                    async(feature = "async", tokio::test(flavor = "multi_thread"))
                )]
                #[serial]
                pub async fn [<test_smbint_ $dialect:lower _e $encrypt_mode:lower>]() -> Result<(), Box<dyn std::error::Error>> {
                    test_smb_integration_basic(Dialect::$dialect, EncryptionMode::$encrypt_mode).await
                }
            }
        )*
    };

    ([$($dialect:ident),*], $encrypt_modes:tt) => {
        $(
            basic_test!([$dialect],  $encrypt_modes);
        )*
    };

}

basic_test!([Smb030, Smb0302, Smb0311], [Disabled, Required]);
basic_test!([Smb0202, Smb021], [Disabled]);

#[maybe_async::maybe_async]
async fn test_smb_integration_basic(
    force_dialect: Dialect,
    encryption_mode: EncryptionMode,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!(
        "Testing with dialect: {:?}, enc? {:?}",
        force_dialect,
        encryption_mode
    );

    let mut smb = Connection::build(ConnectionConfig {
        min_dialect: Some(force_dialect),
        max_dialect: Some(force_dialect),
        encryption_mode,
        ..Default::default()
    })?;
    smb.set_timeout(Some(std::time::Duration::from_secs(10)))
        .await?;
    // Default to localhost, LocalAdmin, 123456
    let server = var("SMB_RUST_TESTS_SERVER").unwrap_or("127.0.0.1:445".to_string());
    let user = var("SMB_RUST_TESTS_USER_NAME").unwrap_or("LocalAdmin".to_string());
    let password = var("SMB_RUST_TESTS_PASSWORD").unwrap_or("123456".to_string());

    info!("Connecting to {} as {}", server, user);

    // Connect & Authenticate
    smb.connect(&server).await?;
    info!("Connected, authenticating...");
    let mut session = smb.authenticate(&user, password).await?;
    info!("Authenticated!");

    // String before ':', after is port:
    let server_name = server.split(':').next().unwrap();
    let mut tree = session
        .tree_connect(format!("\\\\{}\\MyShare", server_name).as_str())
        .await?;
    info!("Connected to share, start test basic");

    const TEST_FILE: &str = "test.txt";
    const TEST_DATA: &[u8] = b"Hello, World!";

    // Hello, World! > test.txt
    {
        let mut file = tree
            .create(
                TEST_FILE,
                CreateDisposition::Create,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            )
            .await?
            .unwrap_file();

        file.write(TEST_DATA).await?;
    }

    // Query directory and make sure our file exists there:
    {
        let dir_info = tree
            .create(
                "",
                CreateDisposition::Open,
                FileAccessMask::new().with_generic_read(true),
            )
            .await?
            .unwrap_dir();
        dir_info
            .query::<FileDirectoryInformation>("*")
            .await?
            .iter()
            .find(|info| info.file_name.to_string() == TEST_FILE)
            .expect("File not found in directory");
    }

    {
        let file = tree
            .create(
                TEST_FILE,
                CreateDisposition::Open,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_delete(true),
            )
            .await?
            .unwrap_file();

        // So anyway it will be deleted at the end.
        file.set_file_info(FileDispositionInformation {
            delete_pending: true.into(),
        })
        .await?;

        let mut buf = [0u8; TEST_DATA.len() + 2];
        let read_length = file.read_block(&mut buf, 0).await?;
        assert_eq!(read_length, TEST_DATA.len());
        assert_eq!(&buf[..read_length], TEST_DATA);

        let all_info = file.query_info::<FileAllInformation>().await?;
        assert_eq!(
            all_info.name.file_name.to_string(),
            "\\".to_string() + TEST_FILE
        );
        assert_eq!(all_info.standard.end_of_file, TEST_DATA.len() as u64);
    }

    Ok(())
}
