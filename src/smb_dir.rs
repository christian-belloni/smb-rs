use crate::{
    msg_handler::*,
    packets::smb2::{dir::*, fscc::*, message::*},
};

use super::smb_resource::SMBHandle;

pub struct SMBDirectory {
    handle: SMBHandle,
    access: DirAccessMask,
}

impl SMBDirectory {
    pub fn new(handle: SMBHandle, access: DirAccessMask) -> Self {
        SMBDirectory { handle, access }
    }

    // Query the directory for it's contents.
    pub fn query(
        &mut self,
        pattern: &str,
    ) -> Result<Vec<BothDirectoryInformationItem>, Box<dyn std::error::Error>> {
        log::debug!("Querying directory {}", self.handle.name());

        let response = self.handle.send_receive(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBQueryDirectoryRequest(SMB2QueryDirectoryRequest {
                file_information_class: FileInformationClass::IdBothDirectoryInformation,
                flags: QueryDirectoryFlags::new().with_restart_scans(true),
                file_index: 0,
                file_id: self.handle.file_id(),
                output_buffer_length: 0x10000,
                file_name: pattern.into(),
            }),
        )))?;

        let content = match response.message.content {
            SMBMessageContent::SMBQueryDirectoryResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let result = match DirectoryInfoVector::parse(
            &content.output_buffer,
            FileInformationClass::IdBothDirectoryInformation,
        )? {
            DirectoryInfoVector::IdBothDirectoryInformation(val) => val,
        };
        Ok(result.into())
    }
}
