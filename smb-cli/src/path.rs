use crate::cli::Cli;
use maybe_async::*;
use smb::{
    connection::{Connection, EncryptionMode},
    packets::{fscc::*, smb2::*},
    resource::Resource,
    session::Session,
    tree::Tree,
    ConnectionConfig,
};
use std::{error::Error, str::FromStr};

#[derive(Debug, Clone)]
pub struct UncPath {
    server: String,
    tree: String,
    path: Option<String>,
}

impl UncPath {
    #[maybe_async]
    pub async fn connect_and_open(
        &self,
        cli: &Cli,
    ) -> Result<(Connection, Session, Tree, Option<Resource>), Box<dyn Error>> {
        // Create a new connection to the server. Use the provided CLI arguments to configure the connection.
        let mut smb = Connection::build(ConnectionConfig {
            max_dialect: Some(Dialect::MAX),
            encryption_mode: EncryptionMode::Allowed,
            timeout: cli
                .timeout
                .map(|t| std::time::Duration::from_secs(t.into())),
            smb2_only_negotiate: cli.negotiate_smb2_only,
            ..Default::default()
        })?;
        smb.connect(format!("{}:{}", self.server, cli.port).as_str())
            .await?;
        let session = smb
            .authenticate(&cli.username, cli.password.clone())
            .await?;
        let tree = session
            .tree_connect(&format!(r"\\{}\{}", self.server, self.tree))
            .await?;
        if let Some(path) = &self.path {
            let file = tree
                .open_existing(
                    path.clone().as_str(),
                    FileAccessMask::new()
                        .with_generic_read(true)
                        .with_generic_write(false),
                )
                .await?;
            Ok((smb, session, tree, Some(file)))
        } else {
            Ok((smb, session, tree, None))
        }
    }
}

impl FromStr for UncPath {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !input.starts_with(r"\\") {
            return Err("UNC path must start with \\\\");
        }
        let parts: Vec<&str> = input[2..].splitn(3, '\\').collect();
        if parts.len() < 2 {
            return Err("UNC path must include at least a server and tree name");
        }
        Ok(UncPath {
            server: parts[0].to_string(),
            tree: parts[1].to_string(),
            path: parts.get(2).map(|s| s.to_string()),
        })
    }
}

/// Remote (UNC) or local path.
#[derive(Debug, Clone)]
pub enum Path {
    Local(std::path::PathBuf),
    Remote(UncPath),
}

impl FromStr for Path {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.starts_with(r"\\") {
            Ok(Path::Remote(input.parse()?))
        } else {
            Ok(Path::Local(std::path::PathBuf::from(input)))
        }
    }
}
