use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::sync_helpers::*;
use smb::{
    packets::{
        fscc::{FileAccessMask, FileAttributes},
        smb2::CreateOptions,
    },
    resource::*,
    Client,
};
use std::error::Error;
use std::f32::consts::E;
#[cfg(not(feature = "async"))]
use std::fs;
#[cfg(feature = "multi_threaded")]
use std::io::Write;

#[cfg(feature = "async")]
use tokio::fs;

#[derive(Parser, Debug)]
pub struct CopyCmd {
    /// Force copy, overwriting existing file(s).
    #[arg(short, long)]
    pub force: bool,

    /// Source path
    pub from: Path,
    /// Destination path
    pub to: Path,
}

enum CopyFile {
    Local(Mutex<fs::File>),
    Remote(File),
}

impl CopyFile {
    #[maybe_async]
    async fn open(
        path: &Path,
        client: &mut Client,
        cli: &Cli,
        cmd: &CopyCmd,
        read: bool,
    ) -> Result<Self, smb::Error> {
        match path {
            Path::Local(path_buf) => {
                let file = fs::OpenOptions::new()
                    .read(read)
                    .write(!read)
                    .create(!read)
                    .create_new(!read && !cmd.force)
                    .truncate(!read)
                    .open(path_buf)
                    .await?;
                Ok(CopyFile::Local(Mutex::new(file)))
            }
            Path::Remote(unc_path) => {
                client
                    .share_connect(unc_path, cli.username.as_str(), cli.password.clone())
                    .await?;
                let create_args = if read {
                    FileCreateArgs::make_open_existing(
                        FileAccessMask::new().with_generic_read(true),
                    )
                } else {
                    FileCreateArgs::make_create_new(
                        FileAttributes::new().with_archive(true),
                        CreateOptions::new(),
                    )
                };
                let file = client
                    .create_file(unc_path, &create_args)
                    .await?
                    .unwrap_file();
                Ok(CopyFile::Remote(file))
            }
        }
    }

    #[maybe_async]
    async fn copy_to(self, to: CopyFile) -> Result<(), smb::Error> {
        match self {
            CopyFile::Local(from_local) => match to {
                CopyFile::Local(to_local) => unreachable!(),
                CopyFile::Remote(to_remote) => {
                    file_util::block_copy(from_local, to_remote, 16).await?
                }
            },
            CopyFile::Remote(from_remote) => match to {
                CopyFile::Local(to_local) => {
                    file_util::block_copy(from_remote, to_local, 16).await?
                }
                CopyFile::Remote(to_remote) => {
                    // TODO: If same connection, use fsctls to copy file in-server.
                    file_util::block_copy(from_remote, to_remote, 8).await?
                }
            },
        }
        Ok(())
    }
}

#[maybe_async]
pub async fn copy(cmd: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if matches!(cmd.from, Path::Local(_)) && matches!(cmd.to, Path::Local(_)) {
        return Err("Copying between two local files is not supported".into());
    }

    let mut client = Client::new(cli.make_smb_client_config());
    let from = CopyFile::open(&cmd.from, &mut client, cli, cmd, true).await?;
    let to = CopyFile::open(&cmd.to, &mut client, cli, cmd, false).await?;
    from.copy_to(to).await?;

    Ok(())
}
