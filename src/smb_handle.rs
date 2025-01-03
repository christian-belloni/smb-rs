use std::{cell::OnceCell, error::Error};

use crate::{
    msg_handler::{OutgoingSMBMessage, SMBHandlerReference, SMBMessageHandler},
    packets::smb2::{
        create::*,
        fscc::FileAttributes,
        message::{SMB2Message, SMBMessageContent},
    },
    smb_dir::SMBDirectory,
    smb_file::SMBFile,
    smb_tree::SMBTreeMessageHandler,
};

type Upstream = SMBHandlerReference<SMBTreeMessageHandler>;

/// An abstract file handle for a "created" SMB2 resource.
///
/// This can be a file, a directory, a named pipe, etc.
pub struct SMBHandle {
    name: String,
    file_id: OnceCell<u128>,
    upstream: Upstream,
}

/// A resource opened by a create request.
pub enum SMBResource {
    File(SMBFile),
    Directory(SMBDirectory),
}

impl SMBResource {
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

impl SMBHandle {
    pub fn new(name: String, upstream: Upstream) -> Self {
        SMBHandle {
            name,
            file_id: OnceCell::default(),
            upstream,
        }
    }

    pub fn create(
        mut self,
        create_disposition: CreateDisposition,
    ) -> Result<SMBResource, Box<dyn Error>> {
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBCreateRequest(SMB2CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                smb_create_flags: 0,
                desired_access: 0x00100081,
                file_attributes: FileAttributes::new(),
                share_access: SMB2ShareAccessFlags::new()
                    .with_read(true)
                    .with_write(true)
                    .with_delete(true),
                create_disposition,
                create_options: 0,
                name: self.name.clone().into(),
                contexts: vec![
                    SMB2CreateContext::new(
                        "DH2Q",
                        vec![
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x20, 0xa3, 0x79, 0xc6, 0xa0, 0xc0, 0xef, 0x11, 0x8b, 0x7b,
                            0x0, 0xc, 0x29, 0x80, 0x16, 0x82,
                        ],
                    ),
                    SMB2CreateContext::new("MxAc", vec![]),
                    SMB2CreateContext::new("QFid", vec![]),
                ],
            }),
        )))?;

        let response = self.receive()?;
        if response.message.header.status != 0 {
            return Err("File creation failed!".into());
        }
        let content = match response.message.content {
            SMBMessageContent::SMBCreateResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        log::info!("Created file {}, (@{})", self.name, content.file_id);

        self.file_id
            .set(content.file_id)
            .map_err(|_| "File ID already set")?;

        let is_dir = content.file_attributes.directory();

        if is_dir {
            Ok(SMBResource::Directory(SMBDirectory::new(self)))
        } else {
            Ok(SMBResource::File(SMBFile::new(self)))
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn file_id(&self) -> Option<u128> {
        self.file_id.get().copied()
    }

    /// Close the handle.
    fn close(&mut self) -> Result<(), Box<dyn Error>> {
        if self.file_id.get().is_none() {
            return Err("Handle not open".into());
        };

        let file_id = self.file_id.take().unwrap();
        log::debug!("Closing handle for {} (@{})", self.name, file_id);
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBCloseRequest(SMB2CloseRequest { file_id }),
        )))?;
        let response = self.receive()?;
        if response.message.header.status != 0 {
            return Err("Handle close failed!".into());
        }

        log::info!("Closed file {}.", self.name);

        Ok(())
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

impl SMBMessageHandler for SMBHandle {
    #[inline]
    fn send(
        &mut self,
        msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        self.upstream.send(msg)
    }

    #[inline]
    fn receive(
        &mut self,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.upstream.receive()
    }
}
