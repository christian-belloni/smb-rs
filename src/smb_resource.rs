use std::error::Error;

use crate::{
    msg_handler::{SMBHandlerReference, SMBMessageHandler},
    packets::smb2::{
        create::*,
        fscc::{FileAccessMask, FileAttributes},
        message::SMBMessageContent,
    },
    smb_dir::SMBDirectory,
    smb_file::SMBFile,
    smb_tree::SMBTreeMessageHandler,
};

type Upstream = SMBHandlerReference<SMBTreeMessageHandler>;

/// A resource opened by a create request.
pub enum SMBResource {
    File(SMBFile),
    Directory(SMBDirectory),
}

impl SMBResource {
    pub fn create(
        name: String,
        mut upstream: Upstream,
        create_disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> Result<SMBResource, Box<dyn Error>> {
        let response =
            upstream.send_recv(SMBMessageContent::SMBCreateRequest(SMB2CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                smb_create_flags: 0,
                desired_access,
                file_attributes: FileAttributes::new(),
                share_access: SMB2ShareAccessFlags::new()
                    .with_read(true)
                    .with_write(true)
                    .with_delete(true),
                create_disposition,
                create_options: 0,
                name: name.clone().into(),
                contexts: vec![
                    SMB2CreateContext::new(CreateContextData::DH2QReq(DH2QReq {
                        timeout: 0,
                        flags: 0,
                        create_guid: 273489604278964,
                    })),
                    SMB2CreateContext::new(CreateContextData::MxAcReq(())),
                    SMB2CreateContext::new(CreateContextData::QFidReq(())),
                ],
            }))?;

        let content = match response.message.content {
            SMBMessageContent::SMBCreateResponse(response) => response,
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
        let handle = SMBHandle {
            name,
            handler: SMBMessageHandleHandler::new(upstream),
            file_id: content.file_id,
        };

        // Construct specific resource and return it.
        if is_dir {
            Ok(SMBResource::Directory(SMBDirectory::new(
                handle,
                access.into(),
            )))
        } else {
            Ok(SMBResource::File(SMBFile::new(
                handle,
                access,
                content.endof_file,
            )))
        }
    }

    pub fn as_file(&self) -> Option<&SMBFile> {
        match self {
            SMBResource::File(f) => Some(f),
            _ => None,
        }
    }

    pub fn as_dir(&self) -> Option<&SMBDirectory> {
        match self {
            SMBResource::Directory(d) => Some(d),
            _ => None,
        }
    }

    pub fn is_file(&self) -> bool {
        self.as_file().is_some()
    }

    pub fn is_dir(&self) -> bool {
        self.as_dir().is_some()
    }

    pub fn unwrap_file(self) -> SMBFile {
        match self {
            SMBResource::File(f) => f,
            _ => panic!("Not a file"),
        }
    }

    pub fn unwrap_dir(self) -> SMBDirectory {
        match self {
            SMBResource::Directory(d) => d,
            _ => panic!("Not a directory"),
        }
    }
}

/// Holds the common information for an opened SMB resource.
pub struct SMBHandle {
    name: String,
    handler: SMBHandlerReference<SMBMessageHandleHandler>,

    file_id: u128,
}

impl SMBHandle {
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
        let _response =
            self.handler
                .send_recv(SMBMessageContent::SMBCloseRequest(SMB2CloseRequest {
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
        msg: SMBMessageContent,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.handler.send_recv(msg)
    }
}

impl Drop for SMBHandle {
    fn drop(&mut self) {
        self.close()
            .or_else(|e| {
                log::error!("Error closing file: {}", e);
                Err(e)
            })
            .ok();
    }
}

struct SMBMessageHandleHandler {
    upstream: Upstream,
}

impl SMBMessageHandleHandler {
    pub fn new(upstream: Upstream) -> SMBHandlerReference<SMBMessageHandleHandler> {
        SMBHandlerReference::new(SMBMessageHandleHandler { upstream })
    }
}

impl SMBMessageHandler for SMBMessageHandleHandler {
    #[inline]
    fn hsendo(
        &mut self,
        msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        self.upstream.borrow_mut().hsendo(msg)
    }

    #[inline]
    fn hrecvo(
        &mut self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.upstream.borrow_mut().hrecvo(options)
    }
}
