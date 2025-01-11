use std::error::Error;

use crate::{
    msg_handler::{HandlerReference, MessageHandler},
    packets::smb2::{
        create::*,
        fscc::{FileAccessMask, FileAttributes},
        message::Content,
    },
    smb_dir::Directory,
    smb_file::File,
    smb_tree::TreeMessageHandler,
};

type Upstream = HandlerReference<TreeMessageHandler>;

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
}

impl Resource {
    pub fn create(
        name: String,
        mut upstream: Upstream,
        create_disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> Result<Resource, Box<dyn Error>> {
        let response = upstream.send_recv(Content::CreateRequest(CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            smb_create_flags: 0,
            desired_access,
            file_attributes: FileAttributes::new(),
            share_access: ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true),
            create_disposition,
            create_options: 0,
            name: name.clone().into(),
            contexts: vec![
                CreateContext::new(CreateContextData::DH2QReq(DH2QReq {
                    timeout: 0,
                    flags: 0,
                    create_guid: 273489604278964,
                })),
                CreateContext::new(CreateContextData::MxAcReq(())),
                CreateContext::new(CreateContextData::QFidReq(())),
            ],
        }))?;

        let content = match response.message.content {
            Content::CreateResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        log::info!("Created file {}, (@{})", name, content.file_id);

        let is_dir = content.file_attributes.directory();

        // Get maximal access
        let access = match content.maximal_access_context() {
            Some(response) => response.maximal_access,
            _ => return Err("MxAc response not found".into()),
        };

        // Common information is held in the handle object.
        let handle = ResourceHandle {
            name,
            handler: MessageHandleHandler::new(upstream),
            file_id: content.file_id,
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

    file_id: u128,
}

impl ResourceHandle {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn file_id(&self) -> u128 {
        self.file_id
    }

    /// Close the handle.
    fn close(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.is_valid() {
            return Err("File ID invalid -- Is this an already closed handle?!".into());
        }

        log::debug!("Closing handle for {} (@{})", self.name, self.file_id);
        let _response = self.handler.send_recv(Content::CloseRequest(CloseRequest {
            file_id: self.file_id,
        }))?;

        self.file_id = u128::MAX;
        log::info!("Closed file {}.", self.name);

        Ok(())
    }

    #[inline]
    pub fn is_valid(&self) -> bool {
        self.file_id != u128::MAX
    }

    /// Send and receive a message, returning the result.
    /// See [SMBHandlerReference::send] and [SMBHandlerReference::receive] for details.
    #[inline]
    pub fn send_receive(
        &mut self,
        msg: Content,
    ) -> Result<crate::msg_handler::IncomingMessage, Box<dyn std::error::Error>> {
        self.handler.send_recv(msg)
    }
}

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

struct MessageHandleHandler {
    upstream: Upstream,
}

impl MessageHandleHandler {
    pub fn new(upstream: Upstream) -> HandlerReference<MessageHandleHandler> {
        HandlerReference::new(MessageHandleHandler { upstream })
    }
}

impl MessageHandler for MessageHandleHandler {
    #[inline]
    fn hsendo(
        &mut self,
        msg: crate::msg_handler::OutgoingMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        self.upstream.borrow_mut().hsendo(msg)
    }

    #[inline]
    fn hrecvo(
        &mut self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> Result<crate::msg_handler::IncomingMessage, Box<dyn std::error::Error>> {
        self.upstream.borrow_mut().hrecvo(options)
    }
}
