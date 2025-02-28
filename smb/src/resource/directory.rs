use crate::{packets::smb2::*, Error};
use maybe_async::*;

use super::ResourceHandle;

pub struct Directory {
    pub handle: ResourceHandle,
    access: DirAccessMask,
}

impl Directory {
    pub fn new(handle: ResourceHandle, access: DirAccessMask) -> Self {
        Directory { handle, access }
    }

    // Query the directory for it's contents.
    #[maybe_async]
    pub async fn query(&mut self, pattern: &str) -> crate::Result<Vec<QueryDirectoryInfo>> {
        if !self.access.list_directory() {
            return Err(Error::MissingPermissions("file_list_directory".to_string()));
        }

        log::debug!("Querying directory {}", self.handle.name());

        let response = self
            .handle
            .send_receive(Content::QueryDirectoryRequest(QueryDirectoryRequest {
                file_information_class: QueryDirectoryInfoClass::IdBothDirectoryInformation,
                flags: QueryDirectoryFlags::new().with_restart_scans(true),
                file_index: 0,
                file_id: self.handle.file_id(),
                output_buffer_length: 0x10000,
                file_name: pattern.into(),
            }))
            .await?;

        let content = match response.message.content {
            Content::QueryDirectoryResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let result = QueryDirectoryInfo::read_output(
            &content.output_buffer,
            QueryDirectoryInfoClass::IdBothDirectoryInformation,
        )
        .unwrap();
        Ok(result.into())
    }
}
