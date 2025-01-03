use crate::{
    msg_handler::*,
    packets::smb2::{dir::*, fscc::*, message::*},
};

use super::smb_handle::SMBHandle;

pub struct SMBDirectory {
    handle: SMBHandle,
}

impl SMBDirectory {
    pub fn new(handle: SMBHandle) -> Self {
        SMBDirectory { handle }
    }

    // Query the directory for it's contents.
    pub fn query(
        &mut self,
        pattern: &str,
    ) -> Result<Vec<BothDirectoryInformationItem>, Box<dyn std::error::Error>> {
        log::debug!("Querying directory {}", self.handle.name());

        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBQueryDirectoryRequest(SMB2QueryDirectoryRequest {
                file_information_class: FileInformationClass::IdBothDirectoryInformation,
                flags: QueryDirectoryFlags::new().with_restart_scans(true),
                file_index: 0,
                file_id: self.handle.file_id().ok_or("File ID not set")?,
                output_buffer_length: 0x10000,
                file_name: pattern.into(),
            }),
        )))?;
        let response = self.receive()?;
        let content = match response.message.content {
            SMBMessageContent::SMBQueryDirectoryResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let result = match DirectoryInfoVector::parse(
            &content.output_buffer,
            FileInformationClass::IdBothDirectoryInformation,
        )? {
            DirectoryInfoVector::IdBothDirectoryInformation(val) => val,
            _ => panic!("Unexpected response"),
        };
        Ok(result.into())
    }
}

impl SMBMessageHandler for SMBDirectory {
    #[inline]
    fn send(
        &mut self,
        msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        self.handle.send(msg)
    }

    #[inline]
    fn receive(
        &mut self,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.handle.receive()
    }
}
