use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::resource::*;
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
fn do_copy(
    from: Box<dyn std::io::Read>,
    to: &mut Box<dyn std::io::Write>,
) -> Result<(), Box<dyn Error>> {
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

#[cfg(feature = "sync")]
pub fn copy(cmd: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let from: Box<dyn std::io::Read> = match &cmd.from {
        Path::Local(path_buf) => Box::new(std::fs::File::create(path_buf)?),
        Path::Remote(unc_path) => {
            let (_client, _session, _tree, mut resource) = unc_path.connect_and_open(cli)?;
            Box::new(
                resource
                    .take()
                    .ok_or("Source file not found")?
                    .unwrap_file(),
            )
        }
    };

    let mut to: Box<dyn std::io::Write> = match &cmd.to {
        Path::Local(path_buf) => Box::new(std::fs::File::create(path_buf)?),
        Path::Remote(unc_path) => {
            let (_client, _session, _tree, mut resource) = unc_path.connect_and_open(cli)?;
            Box::new(
                resource
                    .take()
                    .ok_or("Source file not found")?
                    .unwrap_file(),
            )
        }
    };

    do_copy(from, &mut to)?;

    Ok(())
}
