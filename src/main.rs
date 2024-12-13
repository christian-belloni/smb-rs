use std::error::Error;
use smb::smb_client::SMBClient;


fn main() -> Result<(), Box<dyn Error>> {
    let mut smb = SMBClient::new();
    smb.connect("172.16.204.128:445")?;
    smb.negotiate()?;
    Ok(())
}
