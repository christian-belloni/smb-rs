use std::error::Error;
use smb::smb_client::SMBClient;


fn main() -> Result<(), Box<dyn Error>> {
    let mut smb = SMBClient::new();
    smb.connect("172.16.204.129:445")?;
    smb.negotiate()?;
    let mut session = smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    session.tree_connect(r"\\AVIVVM\MyShare".to_string())?;
    Ok(())
}
