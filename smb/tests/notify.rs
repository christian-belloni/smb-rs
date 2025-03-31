#![cfg(not(feature = "single_threaded"))]
use serial_test::serial;
use smb::{
    connection::EncryptionMode,
    packets::{
        fscc::*,
        smb2::{CreateDisposition, NotifyFilter},
    },
    resource::Resource,
    sync_helpers::*,
    ConnectionConfig,
};
use std::sync::Arc;
mod common;

use common::make_server_connection;
const NEW_FILE_NAME_UNDER_WORKDIR: &str = "test_file.txt";

#[test_log::test(maybe_async::test(
    feature = "sync",
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_smb_notify() -> Result<(), Box<dyn std::error::Error>> {
    let (_connection, _session, tree) = make_server_connection(
        "MyShare",
        ConnectionConfig {
            encryption_mode: EncryptionMode::Disabled,
            ..Default::default()
        }
        .into(),
    )
    .await?;

    // Create the file
    {
        tree.create_file(
            NEW_FILE_NAME_UNDER_WORKDIR,
            CreateDisposition::Create,
            FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true),
        )
        .await?;
    }

    let dir = tree
        .open_existing("", FileAccessMask::new().with_generic_read(true))
        .await?;

    let notified_sem = Arc::new(Semaphore::new(0));
    start_notify_task(notified_sem.clone(), dir);
    // Launch tasks to wait for notifications.
    // Another connection now modifying the file...
    delete_file_from_another_connection("MyShare").await?;
    // Wait for notifiactions to arrive.
    let _p = notified_sem.acquire().await?;
    Ok(())
}

#[maybe_async::async_impl]
fn start_notify_task(sem: Arc<Semaphore>, r: Resource) {
    let filter = NotifyFilter::new()
        .with_file_name(true)
        .with_dir_name(true)
        .with_attributes(true)
        .with_last_write(true)
        .with_last_access(true);
    tokio::spawn(async move {
        for notification in r.unwrap_dir().watch(filter, true).await.unwrap() {
            if notification.action == NotifyAction::Removed {
                sem.add_permits(1);
                break;
            }
        }
    });
}
#[maybe_async::sync_impl]
fn start_notify_task(sem: Arc<Semaphore>, r: Resource) {
    let filter = NotifyFilter::new()
        .with_file_name(true)
        .with_dir_name(true)
        .with_attributes(true)
        .with_last_write(true)
        .with_last_access(true);
    std::thread::spawn(move || {
        for notification in r.unwrap_dir().watch(filter, true).unwrap() {
            if notification.action == NotifyAction::Removed {
                sem.add_permits(1);
                break;
            }
        }
    });
}
#[maybe_async::maybe_async]
async fn delete_file_from_another_connection(
    share_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_connection, _session, tree) = make_server_connection(
        share_name,
        ConnectionConfig {
            encryption_mode: EncryptionMode::Disabled,
            ..Default::default()
        }
        .into(),
    )
    .await?;

    let file = tree
        .open_existing(
            NEW_FILE_NAME_UNDER_WORKDIR,
            FileAccessMask::new()
                .with_generic_all(true)
                .with_delete(true),
        )
        .await?
        .unwrap_file();

    file.set_file_info(FileDispositionInformation {
        delete_pending: true.into(),
    })
    .await?;

    // We are exiting, and file is closed, and deleted!
    Ok(())
}
