use smb::{
    packets::smb2::{create::CreateDisposition, fscc::FileAccessMask},
    client::Client,
};
use std::{error::Error, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut smb = Client::new();
    smb.connect("172.16.204.132:445")?;
    smb.negotiate()?;
    let mut session = smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    let mut tree = session.tree_connect(r"\\AVIVVM\MyShare".to_string())?;
    let file = tree.create(
        "".to_string(),
        CreateDisposition::Open,
        FileAccessMask::new()
            .with_generic_read(true)
            .with_generic_write(true),
    )?;
    match file {
        smb::resource::Resource::File(mut smbfile) => {
            log::info!(
                "File created {}, modified {}",
                smbfile.handle.created(),
                smbfile.handle.modified()
            );

            // Let's read some data from the file.
            let mut buf = [0; 1024];
            let n = smbfile.read(&mut buf)?;
            println!("{:?}", String::from_utf8_lossy(&buf[..n]));

            // Let's write some data to the file.
            smbfile.write_all(b"Hello, world!")?;
        }
        smb::resource::Resource::Directory(mut smbdirectory) => {
            log::info!(
                "Directory created {}, modified {}",
                smbdirectory.handle.created(),
                smbdirectory.handle.modified()
            );

            for (i, item) in smbdirectory.query("*")?.iter().enumerate() {
                log::info!("{i}| {}", item.file_name);
            }
        }
    }
    Ok(())
}
