use smb::{
    client::Client,
    packets::smb2::{create::CreateDisposition, fscc::FileAccessMask},
};
use std::{error::Error, io::prelude::*};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut smb = Client::new();
    smb.connect("172.16.197.128:445")?;
    smb.negotiate()?;
    let mut session = smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    let mut tree = session.tree_connect(r"\\AVIVVM\MyShare".to_string())?;
    let file = tree.create(
        r"hello\d.txt".to_string(),
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

            // Begin by querying more information about this file.
            let info = smbfile.query_info()?;
            log::info!("File info: {:?}", info);

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
                log::info!(
                    "{i}|{} {}",
                    if item.file_attributes.directory() {
                        "d"
                    } else {
                        "f"
                    },
                    item.file_name,
                );
            }
        }
    }
    Ok(())
}
