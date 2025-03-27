use futures_util::StreamExt;
use log::info;
use serial_test::serial;
use smb::{
    connection::EncryptionMode,
    packets::{
        fscc::*,
        smb2::{AdditionalInfo, CreateDisposition, Dialect},
    },
    resource::Directory,
    session::Session,
    tree::Tree,
    Connection, ConnectionConfig,
};
use std::{env::var, sync::Arc};

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

    let (_smb, _session, mut tree) = make_server_connection("MyShare", None).await?;

    const TEST_FILE: &str = "test.txt";
    const TEST_DATA: &[u8] = b"Hello, World!";

    // Hello, World! > test.txt
    let security = {
        let file = tree
            .create_file(
                TEST_FILE,
                CreateDisposition::Create,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            )
            .await?
            .unwrap_file();

        file.write_block(TEST_DATA, 0).await?;

        // Query security info (owner only)
        file.query_security_info(AdditionalInfo::new().with_owner_security_information(true))
            .await?
    };

    if security.owner_sid.is_none() {
        return Err("No owner SID found".into());
    }

    // Query directory and make sure our file exists there:
    {
        let directory = Arc::new(
            tree.open_existing("", FileAccessMask::new().with_generic_read(true))
                .await?
                .unwrap_dir(),
        );
        let mut ds = Directory::query_directory::<FileDirectoryInformation>(&directory, "*");
        let mut found = false;
        while let Some(entry) = ds.next().await {
            if entry?.file_name.to_string() == TEST_FILE {
                found = true;
                break;
            }
        }
        if !found {
            return Err("File not found in directory".into());
        }

        // TODO: Complete Query quota info -- model + fix request encoding.
        // directory
        //     .query_quota_info(QueryQuotaInfo {
        //         return_single: false.into(),
        //         restart_scan: false.into(),
        //         get_quota_info_content: Some(vec![FileGetQuotaInformationInner {
        //             sid: security.owner_sid.unwrap(),
        //         }
        //         .into()]),
        //         sid: None,
        //     })
        //     .await?;
    }

    {
        let file = tree
            .open_existing(
                TEST_FILE,
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
        let read_length = file.read_block(&mut buf, 0, false).await?;
        assert_eq!(read_length, TEST_DATA.len());
        assert_eq!(&buf[..read_length], TEST_DATA);

        // Query file info.
        let all_info = file.query_info::<FileAllInformation>().await?;
        assert_eq!(
            all_info.name.file_name.to_string(),
            "\\".to_string() + TEST_FILE
        );

        // Query filesystem info.
        file.query_fs_info::<FileFsSizeInformation>().await?;

        assert_eq!(all_info.standard.end_of_file, TEST_DATA.len() as u64);
    }

    Ok(())
}

/// This test is to check if we can iterate over a long directory
/// To make sure it works properly, since dealing with streams can be tricky.
#[maybe_async::test(
    feature = "sync",
    async(feature = "async", tokio::test(flavor = "multi_thread"))
)]
#[serial]
async fn test_smb_iterating_long_directory() -> Result<(), Box<dyn std::error::Error>> {
    let (_smb, _session, mut tree) = make_server_connection(
        "MyShare",
        ConnectionConfig {
            encryption_mode: EncryptionMode::Disabled,
            ..Default::default()
        }
        .into(),
    )
    .await?;

    const LONG_DIR: &str = "longdir";
    const NUM_ITEMS: usize = 1000;
    // Mkdir
    tree.create_directory(
        LONG_DIR,
        CreateDisposition::Create,
        FileAccessMask::new().with_generic_read(true),
    )
    .await?
    .unwrap_dir();

    // Create NUM_ITEMS files
    for i in 0..NUM_ITEMS {
        let file_name = format!("{}\\file_{}", LONG_DIR, i);
        let file = tree
            .create_file(
                &file_name,
                CreateDisposition::Create,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            )
            .await?
            .unwrap_file();

        file.write_block(b"Hello, World!", 0).await?;
    }

    // Query directory and make sure our files exist there, delete each file found.
    {
        let directory = Arc::new(
            tree.open_existing(
                LONG_DIR,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_delete(true),
            )
            .await?
            .unwrap_dir(),
        );
        let mut ds = Directory::query_directory::<FileDirectoryInformation>(&directory, "*");
        let mut found = 0;
        while let Some(entry) = ds.next().await {
            let entry = entry?;
            let file_name = entry.file_name.to_string();
            if file_name.starts_with("file_") {
                found += 1;

                // .. And delete the file!
                let full_file_name = format!("{}\\{}", LONG_DIR, file_name);
                let file = tree
                    .open_existing(
                        &full_file_name,
                        FileAccessMask::new()
                            .with_generic_read(true)
                            .with_delete(true),
                    )
                    .await?
                    .unwrap_file();
                file.set_file_info(FileDispositionInformation {
                    delete_pending: true.into(),
                })
                .await?;
            }
        }
        assert_eq!(found, NUM_ITEMS);
    }

    // Cleanup
    {
        let directory = Arc::new(
            tree.open_existing(LONG_DIR, FileAccessMask::new().with_delete(true))
                .await?
                .unwrap_dir(),
        );
        directory
            .set_file_info(FileDispositionInformation {
                delete_pending: true.into(),
            })
            .await?;
    }
    // Wait for the delete to be processed

    Ok(())
}

#[maybe_async::maybe_async]
async fn make_server_connection(
    share: &str,
    config: Option<ConnectionConfig>,
) -> Result<(Connection, Session, Tree), Box<dyn std::error::Error>> {
    let mut smb = Connection::build(config.unwrap_or(Default::default()))?;
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
    let tree = session
        .tree_connect(format!("\\\\{}\\{}", server_name, share).as_str())
        .await?;
    info!("Connected to share, start test basic");

    Ok((smb, session, tree))
}
