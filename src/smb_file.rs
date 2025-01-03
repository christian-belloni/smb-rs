use super::smb_handle::SMBHandle;

pub struct SMBFile {
    handle: SMBHandle,
}

impl SMBFile {
    pub fn new(handle: SMBHandle) -> Self {
        SMBFile { handle }
    }
}
