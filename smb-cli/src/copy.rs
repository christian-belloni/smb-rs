use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb_lib::resource::*;
use std::error::Error;

#[cfg(not(feature = "async"))]
use std::{fs, io};
#[cfg(feature = "async")]
use tokio::{fs, io, io::AsyncRead, io::AsyncReadExt, io::AsyncWrite, io::AsyncWriteExt};

#[derive(Parser, Debug)]
pub struct CopyCmd {
    pub from: Path,
    pub to: Path,
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

    let mut buffered_reader = io::BufReader::with_capacity(32768, file);
    io::copy(&mut buffered_reader, &mut local_file).await?;

    Ok(())
}
