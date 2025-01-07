use std::io::prelude::*;

use crate::{
    msg_handler::{OutgoingSMBMessage, SMBMessageHandler},
    packets::smb2::{
        file::{ReadFlags, SMB2FlushRequest, SMB2ReadRequest, SMB2WriteRequest, WriteFlags},
        message::{SMB2Message, SMBMessageContent},
    },
};

use super::smb_handle::SMBHandle;

pub struct SMBFile {
    handle: SMBHandle,
    pos: u64,
}

impl SMBFile {
    pub fn new(handle: SMBHandle) -> Self {
        assert!(handle.create_response().is_some());
        SMBFile { handle, pos: 0 }
    }
}

impl Seek for SMBFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(pos) => {
                self.pos = pos;
            }
            std::io::SeekFrom::End(pos) => {
                self.pos = self.handle.create_response().unwrap().endof_file as u64 + pos as u64;
            }
            std::io::SeekFrom::Current(pos) => {
                self.pos = self.pos + pos as u64;
            }
        }
        Ok(self.pos)
    }
}

impl Read for SMBFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        log::debug!(
            "Reading up to {} bytes at offset {} from {}",
            buf.len(),
            self.pos,
            self.handle.name()
        );
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBReadRequest(SMB2ReadRequest {
                padding: 0,
                flags: ReadFlags::new(),
                length: buf.len() as u32,
                offset: self.pos,
                file_id: self.handle.create_response().unwrap().file_id,
                minimum_count: 1,
            }),
        )))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let response = self
            .receive()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let content = match response.message.content {
            SMBMessageContent::SMBReadResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let actual_read_length = content.buffer.len();
        self.pos += actual_read_length as u64;
        log::debug!(
            "Read {} bytes from {}.",
            actual_read_length,
            self.handle.name()
        );

        buf[..actual_read_length].copy_from_slice(&content.buffer);

        Ok(actual_read_length)
    }
}

impl Write for SMBFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        log::debug!(
            "Writing {} bytes at offset {} to {}",
            buf.len(),
            self.pos,
            self.handle.name()
        );

        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBWriteRequest(SMB2WriteRequest {
                offset: self.pos,
                file_id: self.handle.create_response().unwrap().file_id,
                flags: WriteFlags::new(),
                buffer: buf.to_vec(),
            }),
        )))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let response = self
            .receive()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if response.message.header.status != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Write failed",
            ));
        }
        let content = match response.message.content {
            SMBMessageContent::SMBWriteResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let actual_written_length = content.count as usize;
        self.pos += actual_written_length as u64;
        log::debug!(
            "Wrote {} bytes to {}.",
            actual_written_length,
            self.handle.name()
        );
        Ok(actual_written_length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBFlushRequest(SMB2FlushRequest {
                file_id: self.handle.create_response().unwrap().file_id,
            }),
        )))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let response = self
            .receive()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if response.message.header.status != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Flush failed",
            ));
        }
        log::debug!("Flushed {}.", self.handle.name());
        Ok(())
    }
}

impl SMBMessageHandler for SMBFile {
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
