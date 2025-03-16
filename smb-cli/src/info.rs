use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::{
    packets::smb2::{FileBasicInformation, FileIdBothDirectoryInformation},
    resource::Resource,
};
use std::error::Error;
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
                let security = file.query_security_info().await?;
                log::info!("Security info: {:?}", security);
            }
            Resource::Directory(dir) => {
                let infos = dir.query::<FileIdBothDirectoryInformation>("*").await?;
                for item in infos.iter() {
                    log::info!(
                        "{} {}",
                        if item.file_attributes.directory() {
                            "d"
                        } else {
                            "f"
                        },
                        item.file_name,
                    );
                }
            }
        };

        client
    }
    .close()
    .await?;

    Ok(())
}
