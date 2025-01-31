use crate::{path::*, Cli};
use clap::Parser;
use std::error::Error;

#[derive(Parser, Debug)]
pub struct CopyCmd {
    pub from: Path,
    pub to: Path,
}
pub fn copy(copy: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    // unwrap from as remote and to as local:
    let from = match &copy.from {
        Path::Remote(remote) => remote,
        _ => return Err("Source path must be remote".into()),
    };
    let to = match &copy.to {
        Path::Local(local) => local,
        _ => return Err("Destination path must be local".into()),
    };

    let (_client, _session, _tree, mut resource) = from.connect_and_open(cli)?;
    let file = resource
        .take()
        .ok_or("Source file not found")?
        .unwrap_file();

    let mut local_file = std::fs::File::create(to)?;
    let mut buffered_reader = std::io::BufReader::with_capacity(32768, file);
    std::io::copy(&mut buffered_reader, &mut local_file)?;

    Ok(())
}
