use std::error::Error;
use smb::smb_client::SMBClient;


fn main() -> Result<(), Box<dyn Error>> {
    let mut smb = SMBClient::new();
    smb.connect("127.0.0.1:445")?;
    smb.negotiate()?;
    smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    smb.tree_connect(r"\\AVIVVM\IPC$".to_string())?;
    Ok(())
}
