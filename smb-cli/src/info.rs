use crate::{path::*, Cli};
use clap::Parser;
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
                let mut info_stream =
                    Directory::query_directory::<FileIdBothDirectoryInformation>(&dir, "*");
                while let Some(info) = info_stream.next().await {
                    match info {
                        Ok(info) => {
                            log::info!("Directory info: {:?}", info);
                        }
                        Err(e) => {
                            log::error!("Error querying directory info: {:?}", e);
                        }
                    }
                }
            }
        };

        client
    }
    .close()
    .await?;

    Ok(())
}
