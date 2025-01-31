use std::error::Error;

use clap::Parser;
use smb_cli::*;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Copy(cmd) => {
            log::info!("Copying {:?} to {:?}", cmd.from, cmd.to);
            copy::copy(&cmd, &cli)?;
        }
        Commands::Info(cmd) => {
            log::info!("Getting info for {:?}", cmd.path);
            info::info(&cmd, &cli)?;
        }
    }

    Ok(())
}
