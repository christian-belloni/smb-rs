use std::{cell::OnceCell, error::Error};

use crate::{
    msg_handler::{OutgoingSMBMessage, SMBHandlerReference, SMBMessageHandler},
    packets::smb2::{
        create::*,
        message::{SMB2Message, SMBMessageContent},
        query_dir::*,
    },
    smb_tree::SMBTreeMessageHandler,
};

type Upstream = SMBHandlerReference<SMBTreeMessageHandler>;

pub struct SMBFile {
    file_name: String,
    file_id: OnceCell<u128>,
    is_dir: OnceCell<bool>,
    upstream: Upstream,
}

impl SMBFile {
    pub fn new(file_name: String, upstream: Upstream) -> Self {
        SMBFile {
            file_name,
            file_id: OnceCell::default(),
            is_dir: OnceCell::default(),
            upstream,
        }
    }

    pub fn create(&mut self) -> Result<(), Box<dyn Error>> {
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBCreateRequest(SMB2CreateRequest {
                requested_oplock_level: OplockLevel::None,
                impersonation_level: ImpersonationLevel::Impersonation,
                smb_create_flags: 0,
                desired_access: 0x00100081,
                file_attributes: 0,
                share_access: SMB2ShareAccessFlags::from_bytes([0x07, 0x00, 0x00, 0x00]),
                create_disposition: CreateDisposition::Open,
                create_options: 0,
                name: self.file_name.encode_utf16().collect(),
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
        log::info!("Created file {}, (@{})", self.file_name, content.file_id);

        self.file_id
            .set(content.file_id)
            .map_err(|_| "File ID already set")?;

        self.is_dir
            .set(content.file_attributes & 0x10 != 0)
            .map_err(|_| "Is dir already set")?;

        Ok(())
    }

    pub fn query(&mut self) -> Result<(), Box<dyn Error>> {
        assert!(self.is_dir.get().unwrap());
        log::debug!("Querying directory {}", self.file_name);

        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBQueryDirectoryRequest(SMB2QueryDirectoryRequest {
                file_information_class: FileInformationClass::BothDirectoryInformation,
                flags: QueryDirectoryFlags::new().with_restart_scans(true),
                file_index: 0,
                file_id: *self.file_id.get().unwrap(),
                output_buffer_length: 0x10000,
                file_name: "*".encode_utf16().collect(),
            }),
        )))?;
        let response = self.receive()?;
        dbg!(&response);
        Ok(())
    }

    fn close(&mut self) -> Result<(), Box<dyn Error>> {
        if self.file_id.get().is_none() {
            return Err("File not open".into());
        };

        let file_id = self.file_id.take().unwrap();
        log::debug!("Closing file {} (@{})", self.file_name, file_id);
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBCloseRequest(SMB2CloseRequest { file_id }),
        )))?;
        let response = self.receive()?;
        if response.message.header.status != 0 {
            return Err("File close failed!".into());
        }

        log::info!("Closed file {}.", self.file_name);

        Ok(())
    }
}

impl Drop for SMBFile {
    fn drop(&mut self) {
        self.close()
            .or_else(|e| {
                log::error!("Error closing file: {}", e);
                Err(e)
            })
            .ok();
    }
}

impl SMBMessageHandler for SMBFile {
    fn send(
        &mut self,
        msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        self.upstream.send(msg)
    }

    fn receive(
        &mut self,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.upstream.receive()
    }
}
