use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::resource::Resource;
use std::error::Error;
#[derive(Parser, Debug)]
pub struct InfoCmd {
    pub path: UncPath,
}

#[maybe_async]
pub async fn info(info: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let (_client, _session, _tree, mut resource) = info.path.connect_and_open(cli).await?;
    let resource = resource.take().ok_or("Resource not found")?;
    match resource {
        Resource::File(file) => {
            let info = file.query_info().await?;
            log::info!("File info: {:?}", info);
        }
        Resource::Directory(mut dir) => {
            for item in dir.query("*").await? {
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
    Ok(())
}
