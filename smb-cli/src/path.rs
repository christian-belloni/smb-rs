use crate::cli::Cli;
use smb_lib::{
    connection::Connection, packets::smb2::*, resource::Resource, session::Session, tree::Tree,
};
use std::{error::Error, str::FromStr};

#[derive(Debug, Clone)]
pub struct UncPath {
    server: String,
    tree: String,
    path: Option<String>,
}

impl UncPath {
    pub fn connect_and_open(
        &self,
        cli: &Cli,
    ) -> Result<(Connection, Session, Tree, Option<Resource>), Box<dyn Error>> {
        let mut smb = Connection::new();
        smb.connect(format!("{}:{}", self.server, cli.port).as_str())?;
        smb.negotiate()?;
        let mut session = smb.authenticate(cli.username.clone(), cli.password.clone())?;
        let mut tree = session.tree_connect(format!(r"\\{}\{}", self.server, self.tree))?;
        if let Some(path) = &self.path {
            let file = tree.create(
                path.clone(),
                CreateDisposition::Open,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(false),
            )?;
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
