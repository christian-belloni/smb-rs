use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb_lib::resource::*;
use std::error::Error;

#[cfg(not(feature = "async"))]
use std::{fs, io};
#[cfg(feature = "async")]
use tokio::{fs, io::AsyncWriteExt};

#[derive(Parser, Debug)]
pub struct CopyCmd {
    pub from: Path,
    pub to: Path,
}

#[sync_impl]
fn do_copy(from: &mut File, to: &mut fs::File) -> Result<(), Box<dyn Error>> {
    let mut buffered_reader = io::BufReader::with_capacity(32768, from);
    io::copy(&mut buffered_reader, to)?;

    Ok(())
}

#[async_impl]
async fn do_copy(from: &mut File, to: &mut fs::File) -> Result<(), Box<dyn Error>> {
    let buffer = &mut [0u8; 32768];
    loop {
        let bytes_read = from.read(buffer).await?;
        if bytes_read == 0 {
            break;
        }
        to.write_all(&buffer[..bytes_read]).await?;
    }

    Ok(())
}

#[maybe_async]
pub async fn copy(copy: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    // unwrap from as remote and to as local:
    let from = match &copy.from {
        Path::Remote(remote) => remote,
        _ => return Err("Source path must be remote".into()),
    };
    let to = match &copy.to {
        Path::Local(local) => local,
        _ => return Err("Destination path must be local".into()),
    };

    let (_client, _session, _tree, mut resource) = from.connect_and_open(cli).await?;
    let mut file = resource
        .take()
        .ok_or("Source file not found")?
        .unwrap_file();

    let mut local_file = fs::File::create(to).await?;

    do_copy(&mut file, &mut local_file).await?;

    Ok(())
}
