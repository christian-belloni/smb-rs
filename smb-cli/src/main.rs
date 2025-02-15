use std::error::Error;

use clap::Parser;
use maybe_async::*;
use smb_cli::*;

#[cfg(feature = "sync")]
fn main() -> Result<(), Box<dyn Error>> {
    _main()
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    _main().await
}

#[maybe_async]
async fn _main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Copy(cmd) => {
            log::info!("Copying {:?} to {:?}", cmd.from, cmd.to);
            copy::copy(&cmd, &cli).await?;
        }
        Commands::Info(cmd) => {
            log::info!("Getting info for {:?}", cmd.path);
            info::info(&cmd, &cli).await?;
        }
    }

    Ok(())
}
