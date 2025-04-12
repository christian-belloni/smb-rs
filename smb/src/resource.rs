use std::sync::Arc;

use maybe_async::*;
use time::PrimitiveDateTime;

use crate::{
    connection::connection_info::ConnectionInfo,
    msg_handler::{HandlerReference, MessageHandler, OutgoingMessage},
    packets::{fscc::*, security::SecurityDescriptor, smb2::*},
    tree::TreeMessageHandler,
    Error,
};

pub mod directory;
pub mod file;

pub use directory::*;
pub use file::*;

type Upstream = HandlerReference<TreeMessageHandler>;

pub struct FileCreateArgs {
    pub disposition: CreateDisposition,
    pub attributes: FileAttributes,
    pub options: CreateOptions,
    pub desired_access: FileAccessMask,
}

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
}

impl Resource {
    #[maybe_async]
    pub(crate) async fn create(
        name: &str,
        upstream: &Upstream,
        create_args: &FileCreateArgs,
        conn_info: &Arc<ConnectionInfo>,
        share_type: ShareType,
        is_dfs: bool,
    ) -> crate::Result<Resource> {
        let share_access = if share_type == ShareType::Disk {
            ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true)
        } else {
            ShareAccessFlags::new()
        };

        if share_type == ShareType::Print && create_args.disposition != CreateDisposition::Create {
            return Err(Error::InvalidArgument(
                "Printer can only accept CreateDisposition::Create.".to_string(),
            ));
        }

        let mut msg = OutgoingMessage::new(Content::CreateRequest(CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: create_args.desired_access,
            file_attributes: create_args.attributes,
            share_access,
            create_disposition: create_args.disposition,
            create_options: create_args.options,
            name: name.into(),
            contexts: vec![
                QueryMaximalAccessRequest::default().into(),
                QueryOnDiskIdReq.into(),
            ],
        }));
        // Make sure to set DFS if required.
        msg.message.header.flags.set_dfs_operation(is_dfs);

        let response = upstream.sendo_recv(msg).await?;

        let content = response.message.content.to_createresponse()?;
        log::info!("Created file '{}', ({:?})", name, content.file_id);

        let is_dir = content.file_attributes.directory();

        // Get maximal access
        let access = match CreateContextRespData::first_mxac(&content.create_contexts) {
            Some(response) => response.maximal_access,
            _ => return Err(Error::InvalidMessage("No maximal access context".into())),
        };

        // Common information is held in the handle object.
        let handle = ResourceHandle {
            name: name.to_string(),
            handler: ResourceMessageHandle::new(upstream),
            file_id: content.file_id,
            created: content.creation_time.date_time(),
            modified: content.last_write_time.date_time(),
            share_type: share_type,
            conn_info: conn_info.clone(),
        };

        // Construct specific resource and return it.

        if is_dir {
            Ok(Resource::Directory(Directory::new(handle, access.into())))
        } else {
            Ok(Resource::File(File::new(
                handle,
                access,
                content.endof_file,
            )))
        }
    }

    pub fn as_file(&self) -> Option<&File> {
        match self {
            Resource::File(f) => Some(f),
            _ => None,
        }
    }

    pub fn as_dir(&self) -> Option<&Directory> {
        match self {
            Resource::Directory(d) => Some(d),
            _ => None,
        }
    }

    pub fn is_file(&self) -> bool {
        self.as_file().is_some()
    }

    pub fn is_dir(&self) -> bool {
        self.as_dir().is_some()
    }

    pub fn unwrap_file(self) -> File {
        match self {
            Resource::File(f) => f,
            _ => panic!("Not a file"),
        }
    }

    pub fn unwrap_dir(self) -> Directory {
        match self {
            Resource::Directory(d) => d,
            _ => panic!("Not a directory"),
        }
    }
}

/// Holds the common information for an opened SMB resource.
pub struct ResourceHandle {
    name: String,
    handler: HandlerReference<ResourceMessageHandle>,

    file_id: FileId,
    created: PrimitiveDateTime,
    modified: PrimitiveDateTime,
    share_type: ShareType,

    conn_info: Arc<ConnectionInfo>,
}

impl ResourceHandle {
    /// Returns the name of the resource.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the creation time of the resource.
    pub fn created(&self) -> PrimitiveDateTime {
        self.created
    }

    /// Returns the last modified time of the resource.
    pub fn modified(&self) -> PrimitiveDateTime {
        self.modified
    }

    /// Returns the current share type of the resource. See [ShareType] for more details.
    pub fn share_type(&self) -> ShareType {
        self.share_type
    }

    /// Internal: Sends a Query Information Request and parses the response.
    #[maybe_async]
    async fn query_common(&self, req: QueryInfoRequest) -> crate::Result<QueryInfoData> {
        let info_type = req.info_type;
        Ok(self
            .send_receive(Content::QueryInfoRequest(req))
            .await?
            .message
            .content
            .to_queryinforesponse()?
            .parse(info_type)?)
    }
    /// Internal: Sends a Set Information Request and parses the response.
    #[maybe_async]
    async fn set_info_common<T>(
        &self,
        data: T,
        cls: SetInfoClass,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()>
    where
        T: Into<SetInfoData>,
    {
        let data = data.into().to_req(cls, self.file_id, additional_info);
        let response = self.send_receive(Content::SetInfoRequest(data)).await?;
        response.message.content.to_setinforesponse()?;
        Ok(())
    }

    /// Queries the file for information.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    /// # Notes
    /// * use [File::query_full_ea_info] to query extended attributes information.
    #[maybe_async]
    pub async fn query_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileInfoValue,
    {
        Ok(self
            .query_common(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(T::CLASS_ID),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.file_id,
                data: GetInfoRequestData::None(()),
            })
            .await?
            .as_file()?
            .parse(T::CLASS_ID)?
            .try_into()?)
    }

    /// Queries the file for extended attributes information.
    /// # Arguments
    /// * `names` - A list of extended attribute names to query.
    /// # Returns
    /// A `Result` containing the requested information, of type [QueryFileFullEaInformation].
    /// See [File::query_info] for more information.
    #[maybe_async]
    pub async fn query_full_ea_info(
        &self,
        names: Vec<&str>,
    ) -> crate::Result<QueryFileFullEaInformation> {
        Ok(self
            .query_common(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.file_id,
                data: GetInfoRequestData::EaInfo(GetEaInfoList {
                    values: names
                        .iter()
                        .map(|&s| FileGetEaInformationInner { ea_name: s.into() }.into())
                        .collect(),
                }),
            })
            .await?
            .as_file()?
            .parse(QueryFileInfoClass::FullEaInformation)?
            .try_into()?)
    }

    /// Queries the file for it's security descriptor.
    /// # Arguments
    /// * `additional_info` - The information to request on the security descriptor.
    /// # Returns
    /// A `Result` containing the requested information, of type [SecurityDescriptor].
    #[maybe_async]
    pub async fn query_security_info(
        &self,
        additional_info: AdditionalInfo,
    ) -> crate::Result<SecurityDescriptor> {
        Ok(self
            .query_common(QueryInfoRequest {
                info_type: InfoType::Security,
                info_class: Default::default(),
                output_buffer_length: 1024,
                additional_info,
                flags: QueryInfoFlags::new(),
                file_id: self.file_id,
                data: GetInfoRequestData::None(()),
            })
            .await?
            .unwrap_security())
    }

    /// Querys the file system information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileSystemInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    #[maybe_async]
    pub async fn query_fs_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileSystemInfoValue,
    {
        if self.share_type != ShareType::Disk {
            return Err(crate::Error::InvalidState(
                "File system information is only available for disk files".into(),
            ));
        }
        Ok(self
            .query_common(QueryInfoRequest {
                info_type: InfoType::FileSystem,
                info_class: QueryInfoClass::FileSystem(T::CLASS_ID),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.file_id,
                data: GetInfoRequestData::None(()),
            })
            .await?
            .unwrap_filesystem()
            .parse(T::CLASS_ID)?
            .try_into()?)
    }

    /// Sets the file information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to set. Must implement the [SetFileInfoValue] trait.
    #[maybe_async]
    pub async fn set_file_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileInfoValue,
    {
        self.set_info_common(
            RawSetInfoData::from(info.into()),
            T::CLASS_ID.into(),
            Default::default(),
        )
        .await
    }

    /// Sets the file system information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to set. Must implement the [SetFileSystemInfoValue] trait.
    #[maybe_async]
    pub async fn set_filesystem_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileSystemInfoValue,
    {
        if self.share_type != ShareType::Disk {
            return Err(crate::Error::InvalidState(
                "File system information is only available for disk files".into(),
            ));
        }

        self.set_info_common(
            RawSetInfoData::from(info.into()),
            T::CLASS_ID.into(),
            Default::default(),
        )
        .await
    }

    /// Sets the file system information for the current file.
    /// # Arguments
    /// * `info` - The information to set - a [SecurityDescriptor].
    /// * `additional_info` - The information that is set on the security descriptor.
    #[maybe_async]
    pub async fn set_security_info(
        &self,
        info: SecurityDescriptor,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()> {
        self.set_info_common(
            info,
            SetInfoClass::Security(Default::default()),
            additional_info,
        )
        .await
    }

    /// Close the handle.
    #[maybe_async]
    async fn close(&mut self) -> crate::Result<()> {
        if !self.is_valid() {
            return Err(Error::InvalidState("Handle is not valid".into()));
        }

        log::debug!("Closing handle for {} ({:?})", self.name, self.file_id);
        let _response = self
            .handler
            .send_recv(Content::CloseRequest(CloseRequest {
                file_id: self.file_id,
            }))
            .await?;

        self.file_id = FileId::EMPTY;
        log::info!("Closed file {}.", self.name);

        Ok(())
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.file_id != FileId::EMPTY
    }

    #[maybe_async]
    #[inline]
    pub async fn send_receive(
        &self,
        msg: Content,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.handler.send_recv(msg).await
    }

    #[cfg(feature = "async")]
    pub async fn close_async(&mut self) {
        self.close()
            .await
            .or_else(|e| {
                log::error!("Error closing file: {}", e);
                Err(e)
            })
            .ok();
    }
}

struct ResourceMessageHandle {
    upstream: Upstream,
}

impl ResourceMessageHandle {
    pub fn new(upstream: &Upstream) -> HandlerReference<ResourceMessageHandle> {
        HandlerReference::new(ResourceMessageHandle {
            upstream: upstream.clone(),
        })
    }
}

impl MessageHandler for ResourceMessageHandle {
    #[maybe_async]
    #[inline]
    async fn sendo(
        &self,
        msg: crate::msg_handler::OutgoingMessage,
    ) -> crate::Result<crate::msg_handler::SendMessageResult> {
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    #[inline]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.upstream.recvo(options).await
    }
}

#[cfg(feature = "sync")]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        self.close()
            .or_else(|e| {
                log::error!("Error closing file: {}", e);
                Err(e)
            })
            .ok();
    }
}

#[cfg(feature = "async")]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.close_async().await;
            })
        })
    }
}
