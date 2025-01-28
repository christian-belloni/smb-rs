use clap::{Parser, Subcommand};
use smb_lib::{
    client::Client,
    packets::smb2::{create::CreateDisposition, fscc::FileAccessMask},
    resource::Resource,
    session::Session,
    tree::Tree,
};
use std::{error::Error, str::FromStr};

#[derive(Debug, Clone)]
struct UncPath {
    server: String,
    tree: String,
    path: Option<String>,
}

impl UncPath {
    fn connect_and_open(
        &self,
        cli: &Cli,
    ) -> Result<(Client, Session, Tree, Option<Resource>), Box<dyn Error>> {
        let mut smb = Client::new();
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

#[derive(Debug, Clone)]
enum Path {
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

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "445")]
    port: u16,

    #[arg(short, long)]
    username: String,
    #[arg(short, long)]
    password: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
struct CopyCmd {
    from: Path,
    to: Path,
}

#[derive(Parser, Debug)]
struct InfoCmd {
    path: UncPath,
}

#[derive(Subcommand)]
enum Commands {
    Copy(CopyCmd),
    Info(InfoCmd),
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let cli = Cli::parse();
    match &cli.command {
        Commands::Copy(cmd) => {
            log::info!("Copying {:?} to {:?}", cmd.from, cmd.to);
            copy(&cmd, &cli)?;
        }
        Commands::Info(cmd) => {
            log::info!("Getting info for {:?}", cmd.path);
            info(&cmd, &cli)?;
        }
    }

    Ok(())
}

fn copy(copy: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
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

fn info(info: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let (_client, _session, _tree, mut resource) = info.path.connect_and_open(cli)?;
    let resource = resource.take().ok_or("Resource not found")?;
    match resource {
        Resource::File(mut file) => {
            let info = file.query_info()?;
            log::info!("File info: {:?}", info);
        }
        Resource::Directory(mut dir) => {
            for item in dir.query("*")? {
                log::info!(
                    "{} {}",
                    if item.file_attributes.directory() {
                        "d"
                    } else {
                        "f"
                    },
                    item.file_name,
                );
            }
        }
    };
    Ok(())
}
