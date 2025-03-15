use maybe_async::*;
use time::PrimitiveDateTime;

use crate::{
    msg_handler::{HandlerReference, MessageHandler},
    packets::{guid::Guid, smb2::*},
    tree::TreeMessageHandler,
    Error,
};

pub mod directory;
pub mod file;

pub use directory::*;
pub use file::*;

type Upstream = HandlerReference<TreeMessageHandler>;

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
}

impl Resource {
    #[maybe_async]
    pub async fn create(
        name: &str,
        upstream: Upstream,
        create_disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        let response = upstream
            .send_recv(Content::CreateRequest(CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                desired_access,
                file_attributes: FileAttributes::new(),
                share_access: ShareAccessFlags::new()
                    .with_read(true)
                    .with_write(true)
                    .with_delete(true),
                create_disposition,
                create_options: CreateOptions::new(),
                name: name.into(),
                contexts: vec![
                    DH2QReq {
                        timeout: 0,
                        flags: DH2QFlags::new(),
                        create_guid: Guid::try_from(&[
                            180, 122, 182, 194, 188, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        ])
                        .unwrap(),
                    }
                    .into(),
                    MxAcReq.into(),
                    QFidReq.into(),
                ],
            }))
            .await?;

        let content = match response.message.content {
            Content::CreateResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        log::info!("Created file '{}', ({})", name, content.file_id);

        let is_dir = content.file_attributes.directory();

        // Get maximal access
        let access = match CreateContextRespData::first_mxac(&content.create_contexts) {
            Some(response) => response.maximal_access,
            _ => return Err(Error::InvalidMessage("No maximal access context".into())),
        };

        // Common information is held in the handle object.
        let handle = ResourceHandle {
            name: name.to_string(),
            handler: MessageHandleHandler::new(upstream),
            file_id: content.file_id,
            created: content.creation_time.date_time(),
            modified: content.last_write_time.date_time(),
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
    handler: HandlerReference<MessageHandleHandler>,

    file_id: Guid,
    created: PrimitiveDateTime,
    modified: PrimitiveDateTime,
}

impl ResourceHandle {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn file_id(&self) -> Guid {
        self.file_id
    }

    pub fn created(&self) -> PrimitiveDateTime {
        self.created
    }

    pub fn modified(&self) -> PrimitiveDateTime {
        self.modified
    }

    /// Close the handle.
    #[maybe_async]
    async fn close(&mut self) -> crate::Result<()> {
        if !self.is_valid() {
            return Err(Error::InvalidState("Handle is not valid".into()));
        }

        log::debug!("Closing handle for {} ({})", self.name, self.file_id);
        let _response = self
            .handler
            .send_recv(Content::CloseRequest(CloseRequest {
                file_id: self.file_id,
            }))
            .await?;

        self.file_id = Guid::MAX;
        log::info!("Closed file {}.", self.name);

        Ok(())
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.file_id != Guid::MAX
    }

    /// Send and receive a message, returning the result.
    /// See [SMBHandlerReference::send] and [SMBHandlerReference::receive] for details.
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

struct MessageHandleHandler {
    upstream: Upstream,
}

impl MessageHandleHandler {
    pub fn new(upstream: Upstream) -> HandlerReference<MessageHandleHandler> {
        HandlerReference::new(MessageHandleHandler { upstream })
    }
}

impl MessageHandler for MessageHandleHandler {
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
        options: crate::msg_handler::ReceiveOptions,
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
