use std::error::Error;
use smb::smb_client::SMBClient;


fn main() -> Result<(), Box<dyn Error>> {
    let mut smb = SMBClient::new();
    smb.connect("172.16.204.131:445")?;
    smb.negotiate()?;
    smb.authenticate("LocalAdmin".to_string(), "123456".to_string())?;
    Ok(())
}
