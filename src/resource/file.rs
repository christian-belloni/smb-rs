use std::io::prelude::*;

use crate::packets::smb2::{file::*, fscc::*, info::*, plain::*};

use super::*;

pub struct File {
    pub handle: ResourceHandle,

    pos: u64,
    dirty: bool,

    access: FileAccessMask,
    end_of_file: u64,
}

impl File {
    pub fn new(handle: ResourceHandle, access: FileAccessMask, end_of_file: u64) -> Self {
        File {
            handle,
            pos: 0,
            dirty: false,
            access,
            end_of_file,
        }
    }

    pub fn query_info(&mut self) -> Result<FileBasicInformation, Box<dyn std::error::Error>> {
        let response = self
            .handle
            .send_receive(Content::QueryInfoRequest(QueryInfoRequest {
                info_type: QueryInfoType::File,
                file_info_class: FileInfoClass::BasicInformation,
                output_buffer_length: 1024,
                additional_information: QueryAdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
                data: QueryInfoRequestData::None(()),
            }))?;
        let query_info_response = match response.message.content {
            Content::QueryInfoResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let result = query_info_response
            .parse(QueryInfoType::File)?
            .unwrap_file()
            .parse(FileInfoClass::BasicInformation)?;
        let result = match result {
            FileInfo::BasicInformation(val) => val,
            _ => panic!("Unexpected response"),
        };
        Ok(result)
    }
}

impl Seek for File {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(pos) => {
                self.pos = pos;
            }
            std::io::SeekFrom::End(pos) => {
                self.pos = self.end_of_file + pos as u64;
            }
            std::io::SeekFrom::Current(pos) => {
                self.pos = self.pos + pos as u64;
            }
        }
        Ok(self.pos)
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.access.file_read_data() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "No read permission",
            ));
        }

        log::debug!(
            "Reading up to {} bytes at offset {} from {}",
            buf.len(),
            self.pos,
            self.handle.name()
        );
        let response = self
            .handle
            .send_receive(Content::ReadRequest(ReadRequest {
                padding: 0,
                flags: ReadFlags::new().with_read_compressed(true),
                length: buf.len() as u32,
                offset: self.pos,
                file_id: self.handle.file_id(),
                minimum_count: 1,
            }))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let content = match response.message.content {
            Content::ReadResponse(response) => response,
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

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.access.file_write_data() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "No write permission",
            ));
        }

        log::debug!(
            "Writing {} bytes at offset {} to {}",
            buf.len(),
            self.pos,
            self.handle.name()
        );

        let response = self
            .handle
            .send_receive(Content::WriteRequest(WriteRequest {
                offset: self.pos,
                file_id: self.handle.file_id(),
                flags: WriteFlags::new(),
                buffer: buf.to_vec(),
            }))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let content = match response.message.content {
            Content::WriteResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let actual_written_length = content.count as usize;
        self.pos += actual_written_length as u64;
        self.dirty = true;
        log::debug!(
            "Wrote {} bytes to {}.",
            actual_written_length,
            self.handle.name()
        );
        Ok(actual_written_length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Well, no need to flush if nothing has been written...
        if !self.dirty {
            return Ok(());
        }

        let _response = self
            .handle
            .send_receive(Content::FlushRequest(FlushRequest {
                file_id: self.handle.file_id(),
            }))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        log::debug!("Flushed {}.", self.handle.name());
        Ok(())
    }
}
