use crate::{
    packets::{fscc::*, smb2::*},
    Error,
};
use maybe_async::*;

use super::ResourceHandle;

/// A directory resource on the server.
/// This is used to query the directory for its contents,
/// and may not be created directly -- but via [Resource][super::Resource], opened
/// from a [Tree][crate::tree::Tree]
pub struct Directory {
    pub handle: ResourceHandle,
    access: DirAccessMask,
}

impl Directory {
    pub fn new(handle: ResourceHandle, access: DirAccessMask) -> Self {
        Directory { handle, access }
    }

    /// Performs a query on the directory.
    #[maybe_async]
    async fn send_query<T>(&self, pattern: &str, restart: bool) -> crate::Result<Vec<T>>
    where
        T: QueryDirectoryInfoValue,
    {
        if !self.access.list_directory() {
            return Err(Error::MissingPermissions("file_list_directory".to_string()));
        }

        log::debug!("Querying directory {}", self.handle.name());

        let response = self
            .handle
            .send_receive(Content::QueryDirectoryRequest(QueryDirectoryRequest {
                file_information_class: T::CLASS_ID,
                flags: QueryDirectoryFlags::new().with_restart_scans(restart),
                file_index: 0,
                file_id: self.handle.file_id(),
                output_buffer_length: 0x10000,
                file_name: pattern.into(),
            }))
            .await?;

        Ok(response
            .message
            .content
            .to_querydirectoryresponse()?
            .read_output()?)
    }

    #[maybe_async]
    pub async fn query_quota_info(&self, info: QueryQuotaInfo) -> crate::Result<QueryQuotaInfo> {
        Ok(self
            .handle
            .query_common(QueryInfoRequest {
                info_type: InfoType::Quota,
                info_class: Default::default(),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
                data: GetInfoRequestData::Quota(info),
            })
            .await?
            .unwrap_quota())
    }

    /// Sets the quota information for the current file.
    /// # Arguments
    /// * `info` - The information to set - a [QueryQuotaInfo].
    #[maybe_async]
    pub async fn set_quota_info(&self, info: QueryQuotaInfo) -> crate::Result<()> {
        self.handle
            .set_info_common(
                info,
                SetInfoClass::Quota(Default::default()),
                Default::default(),
            )
            .await
    }
}
