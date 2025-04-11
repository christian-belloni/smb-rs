use crate::cli::Cli;
use maybe_async::*;
use smb::{
    connection::{Connection, EncryptionMode},
    packets::{dfsc::ReferralEntryValue, fscc::*, smb2::*},
    resource::Resource,
    session::Session,
    tree::{DfsRootTree, Tree},
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
    /// Connects to the server and opens the specified share.
    /// Returns the connection, session, tree, and a resource, if the given
    /// UNC path provides a valid path.
    ///
    /// * Resolved DFS referrals.
    #[maybe_async]
    pub async fn connect_and_open(
        &self,
        cli: &Cli,
    ) -> Result<(Connection, Session, Tree, Option<Resource>), Box<dyn Error>> {
        // Create a new connection to the server. Use the provided CLI arguments to configure the connection.
        let (conn, session, tree) = self.open_share(cli).await?;
        if let Some(path) = &self.path {
            let open_result = tree
                .open_existing(
                    path.clone().as_str(),
                    FileAccessMask::new()
                        .with_generic_read(true)
                        .with_generic_write(false),
                )
                .await;

            // DFS: Handle Status::PathNotCovered by resolving and opening the target DFS path.
            const STATUS_PATH_NOT_COVERED: u32 = Status::PathNotCovered as u32;
            let next_unc = match open_result {
                Ok(f) => {
                    return Ok((conn, session, tree, Some(f)));
                }
                Err(e) => match e {
                    smb::Error::ReceivedErrorMessage(STATUS_PATH_NOT_COVERED, _) => {
                        let dfs_root = tree.into_dfs_tree()?;
                        self.resolve_next_dfs_ref(&dfs_root).await?
                    }
                    e => return Err(e.into()),
                },
            };

            // Open the next DFS referral.
            let (dfs_conn, dfs_session, dfs_tree) = next_unc.open_share(cli).await?;
            let dfs_file = dfs_tree
                .open_existing(
                    next_unc.path.as_ref().unwrap(),
                    FileAccessMask::new()
                        .with_generic_read(true)
                        .with_generic_write(false),
                )
                .await?;
            Ok((dfs_conn, dfs_session, dfs_tree, Some(dfs_file)))
        } else {
            Ok((conn, session, tree, None))
        }
    }

    /// Opens a share on the server using the provided CLI arguments.
    /// Returns the connection, session, and tree instances.
    #[maybe_async]
    async fn open_share(&self, cli: &Cli) -> Result<(Connection, Session, Tree), Box<dyn Error>> {
        log::debug!("Opening the share \\\\{}\\{}", self.server, self.tree);
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

        Ok((smb, session, tree))
    }

    /// Resolves the next DFS referral for the given UNC path.
    #[maybe_async]
    async fn resolve_next_dfs_ref(
        &self,
        dfs_root: &DfsRootTree,
    ) -> Result<UncPath, Box<dyn Error>> {
        log::debug!("Resolving DFS referral for {}", self.to_string());
        let this_as_string = self.to_string();
        let dfs_refs = dfs_root.dfs_get_referrals(&this_as_string).await?;
        if !dfs_refs.referral_header_flags.storage_servers() {
            return Err(smb::Error::InvalidState(
                "DFS referral does not contain storage servers".to_string(),
            )
            .into());
        }
        let main_node_ref = &dfs_refs.referral_entries[0];
        match &main_node_ref.value {
            ReferralEntryValue::V4(v4) => {
                if v4.referral_entry_flags == 0 {
                    return Err(smb::Error::InvalidState(
                        "First DFS Referral is not primary one, invalid message!".to_string(),
                    )
                    .into());
                }
                // The path consumed is a wstring index.
                let index_end_of_match =
                    dfs_refs.path_consumed as usize / std::mem::size_of::<u16>();

                if index_end_of_match > this_as_string.len() {
                    return Err(smb::Error::InvalidState(
                        "DFS path consumed is out of bounds".to_string(),
                    )
                    .into());
                }

                let suffix = if index_end_of_match < this_as_string.len() {
                    this_as_string
                        .char_indices()
                        .nth(index_end_of_match)
                        .ok_or_else(|| {
                            smb::Error::InvalidState(
                                "DFS path consumed is out of bounds".to_string(),
                            )
                        })?
                        .0
                } else {
                    // Empty -- exact cover.
                    this_as_string.len()
                };

                let unc_str_dest = "\\".to_string()
                    + &v4.refs.network_address.to_string()
                    + &this_as_string[suffix..];
                let unc_path = UncPath::from_str(&unc_str_dest)?;
                log::debug!("Resolved DFS referral to {}", unc_path.to_string());
                Ok(unc_path)
            }
            _ => {
                return Err(smb::Error::InvalidState(
                    "Unsupported DFS referral entry value".to_string(),
                )
                .into());
            }
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

impl ToString for UncPath {
    fn to_string(&self) -> String {
        let mut unc = format!(r"\\{}\{}", self.server, self.tree);
        if let Some(path) = &self.path {
            unc.push_str(&format!(r"\{}", path));
        }
        unc
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
