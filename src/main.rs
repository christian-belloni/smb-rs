use smb::smb_client::SMBClient;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut smb = SMBClient::new();
    smb.connect("172.16.197.128:445")?;
    smb.negotiate()?;
    let mut session = smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    let mut tree = session.tree_connect(r"\\AVIVVM\MyShare".to_string())?;
    tree.create("hello".to_string())?;
    Ok(())
}
