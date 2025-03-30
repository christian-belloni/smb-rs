use crate::{copy::CopyCmd, info::InfoCmd};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long, default_value = "445")]
    pub port: u16,

    #[arg(long)]
    pub timeout: Option<u16>,

    #[arg(short, long)]
    pub username: String,
    #[arg(short, long)]
    pub password: String,

    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand)]
pub enum Commands {
    Copy(CopyCmd),
    Info(InfoCmd),
}
