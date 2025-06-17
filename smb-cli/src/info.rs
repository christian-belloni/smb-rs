use crate::Cli;
use clap::Parser;
#[cfg(feature = "async")]
use futures_util::StreamExt;
use maybe_async::*;
use smb::{
    packets::{fscc::*, smb2::AdditionalInfo},
    resource::{Directory, Resource},
    Client, FileCreateArgs, UncPath,
};
use std::{error::Error, sync::Arc};
#[derive(Parser, Debug)]
pub struct InfoCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: UncPath,
}

#[maybe_async]
pub async fn info(info: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let mut client = Client::new(cli.make_smb_client_config());

    if info.path.share.is_none() || info.path.share.as_ref().unwrap().is_empty() {
        client
            .ipc_connect(&info.path.server, &cli.username, cli.password.clone())
            .await?;
        let shares_info = client.list_shares(&info.path.server).await?;
        log::info!("Available shares on {}: ", info.path.server);
        for share in shares_info {
            log::info!("  - {}", **share.netname.as_ref().unwrap());
        }
        return Ok(());
    }

    client
        .share_connect(&info.path, cli.username.as_ref(), cli.password.clone())
        .await?;
    let resource = client
        .create_file(
            &info.path,
            &FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true)),
        )
        .await?;

    match resource {
        Resource::File(file) => {
            let info: FileBasicInformation = file.query_info().await?;
            log::info!("File info: {info:?}");
            let security = file
                .query_security_info(AdditionalInfo::new().with_owner_security_information(true))
                .await?;
            log::info!("Security info: {security:?}");
        }
        Resource::Directory(dir) => {
            let dir = Arc::new(dir);
            iterate_directory(&dir, "*", |info| {
                log::info!("Directory info: {info:?}");
                Ok(())
            })
            .await?;
        }
        Resource::Pipe(_) => {
            log::info!("Pipe (no information)");
        }
    };

    client.close().await?;

    Ok(())
}

#[maybe_async::sync_impl]
fn iterate_directory(
    dir: &Arc<Directory>,
    pattern: &str,
    func: impl Fn(&FileIdBothDirectoryInformation) -> smb::Result<()>,
) -> smb::Result<()> {
    for info in Directory::query_directory::<FileIdBothDirectoryInformation>(dir, pattern)? {
        func(&info?)?;
    }
    Ok(())
}

#[maybe_async::async_impl]
async fn iterate_directory(
    dir: &Arc<Directory>,
    pattern: &str,
    func: impl Fn(&FileIdBothDirectoryInformation) -> smb::Result<()>,
) -> smb::Result<()> {
    let mut info_stream =
        Directory::query_directory::<FileIdBothDirectoryInformation>(dir, pattern).await?;
    while let Some(info) = info_stream.next().await {
        func(&info?)?;
    }
    Ok(())
}
