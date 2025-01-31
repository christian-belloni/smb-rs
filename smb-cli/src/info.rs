use crate::{path::*, Cli};
use clap::Parser;
use smb_lib::resource::Resource;
use std::error::Error;

#[derive(Parser, Debug)]
pub struct InfoCmd {
    pub path: UncPath,
}

pub fn info(info: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let (_client, _session, _tree, mut resource) = info.path.connect_and_open(cli)?;
    let resource = resource.take().ok_or("Resource not found")?;
    match resource {
        Resource::File(mut file) => {
            let info = file.query_info()?;
            log::info!("File info: {:?}", info);
        }
        Resource::Directory(mut dir) => {
            for item in dir.query("*")? {
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
