#![cfg(all(feature = "sign", feature = "encrypt"))]

use serial_test::serial;
use smb::{
    connection::EncryptionMode,
    packets::{fscc::*, smb2::CreateDisposition},
    resource::Directory,
    tree::Tree,
    ConnectionConfig,
};
use std::sync::Arc;

#[cfg(feature = "async")]
use futures_util::StreamExt;
mod common;
use common::make_server_connection;

const LONG_DIR: &str = "longdir";
const NUM_ITEMS: usize = 1000;

/// This test is to check if we can iterate over a long directory
/// To make sure it works properly, since dealing with streams can be tricky.
#[test_log::test(maybe_async::test(
    feature = "sync",
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial] // Run only in a full-feature test, because it takes a while
async fn test_smb_iterating_long_directory() -> Result<(), Box<dyn std::error::Error>> {
    let (_smb, _session, tree) = make_server_connection(
        "MyShare",
        ConnectionConfig {
            encryption_mode: EncryptionMode::Disabled,
            ..Default::default()
        }
        .into(),
    )
    .await?;

    let tree = Arc::new(tree);
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
        tree.create_file(&file_name, CreateDisposition::Create, FileAccessMask::new())
            .await?
            .unwrap_file();
    }

    // Query directory and make sure our files exist there, delete each file found.
    {
        let directory = tree
            .open_existing(
                LONG_DIR,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_delete(true),
            )
            .await?
            .unwrap_dir();
        let directory = Arc::new(directory);
        let found =
            Directory::query_directory::<FileFullDirectoryInformation>(&directory, "file_*")
                .await?
                .fold(0, |sum, entry| {
                    let tree = tree.clone();
                    async move {
                        let entry = entry.unwrap();
                        let file_name = entry.file_name.to_string();
                        assert!(file_name.starts_with("file_"));
                        let file_number: usize = file_name[5..].parse().unwrap();
                        assert!(file_number < NUM_ITEMS);

                        // .. And delete the file!
                        let full_file_name = format!("{}\\{}", LONG_DIR, file_name);
                        let file = tree
                            .open_existing(
                                &full_file_name,
                                FileAccessMask::new()
                                    .with_generic_read(true)
                                    .with_delete(true),
                            )
                            .await
                            .unwrap()
                            .unwrap_file();
                        file.set_file_info(FileDispositionInformation {
                            delete_pending: true.into(),
                        })
                        .await
                        .unwrap();
                        sum + 1
                    }
                })
                .await;
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
pub async fn remove_file_by_name(tree: &Tree, file_name: &str) -> smb::Result<()> {
    let file = tree
        .open_existing(
            file_name,
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
    Ok(())
}
