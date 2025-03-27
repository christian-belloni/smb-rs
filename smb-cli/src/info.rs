use crate::{path::*, Cli};
use clap::Parser;
#[cfg(feature = "async")]
use futures_util::StreamExt;
use maybe_async::*;
use smb::{
    packets::{fscc::*, smb2::AdditionalInfo},
    resource::{Directory, Resource},
};
use std::{error::Error, sync::Arc};
#[derive(Parser, Debug)]
pub struct InfoCmd {
    pub path: UncPath,
}

#[maybe_async]
pub async fn info(info: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    {
        let (client, _session, _tree, mut resource) = info.path.connect_and_open(cli).await?;
        let resource = resource.take().ok_or("Resource not found")?;
        match resource {
            Resource::File(file) => {
                let info: FileBasicInformation = file.query_info().await?;
                log::info!("File info: {:?}", info);
                let security = file
                    .query_security_info(
                        AdditionalInfo::new().with_owner_security_information(true),
                    )
                    .await?;
                log::info!("Security info: {:?}", security);
            }
            Resource::Directory(dir) => {
                let dir = Arc::new(dir);
                iterate_directory(&dir, "*", |info| {
                    log::info!("Directory info: {:?}", info);
                    Ok(())
                })
                .await?;
            }
        };

        client
    }
    .close()
    .await?;

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
