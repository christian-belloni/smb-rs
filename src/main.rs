use smb::smb_client::SMBClient;
use std::{error::Error, io::Read};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut smb = SMBClient::new();
    smb.connect("172.16.204.132:445")?;
    smb.negotiate()?;
    let mut session = smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    let mut tree = session.tree_connect(r"\\AVIVVM\MyShare".to_string())?;
    let file = tree.create("hello.txt".to_string())?;
    match file {
        smb::smb_handle::SMBResource::File(mut smbfile) => {
            let mut buf = [0u8; 0x1000];
            let n = smbfile.read(&mut buf)?;
            println!("{:?}", String::from_utf8_lossy(&buf[..n]));
        }
        smb::smb_handle::SMBResource::Directory(mut smbdirectory) => {
            for item in smbdirectory.query("*")? {
                println!("{:?}", item);
            }
        }
    }
    Ok(())
}
