use super::*;
use maybe_async::*;
use std::io::prelude::*;

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

    #[maybe_async]
    pub async fn query_info(&mut self) -> Result<FileBasicInformation, Box<dyn std::error::Error>> {
        let response = self
            .handle
            .send_receive(Content::QueryInfoRequest(QueryInfoRequest {
                info_type: InfoType::File,
                file_info_class: QueryFileInfoClass::BasicInformation,
                output_buffer_length: 1024,
                additional_information: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
                data: GetInfoRequestData::None(()),
            }))
            .await?;
        let query_info_response = match response.message.content {
            Content::QueryInfoResponse(response) => response,
            _ => panic!("Unexpected response"),
        };
        let result = query_info_response
            .parse(InfoType::File)?
            .unwrap_file()
            .parse(QueryFileInfoClass::BasicInformation)?;
        let result = match result {
            QueryFileInfo::BasicInformation(val) => val,
            _ => panic!("Unexpected response"),
        };
        Ok(result)
    }

    #[maybe_async]
    /// Reads up to `buf.len()` bytes from the file into `buf`.
    /// This is the same as `std::io::Read::read`, but async when enabled.
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.access.file_read_data() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "No read permission",
            ));
        }

        // EOF
        if self.pos >= self.end_of_file {
            return Ok(0);
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
            .await
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

    #[maybe_async]
    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
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
            .await
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

    #[maybe_async]
    pub async fn flush(&mut self) -> std::io::Result<()> {
        // Well, no need to flush if nothing has been written...
        if !self.dirty {
            return Ok(());
        }

        let _response = self
            .handle
            .send_receive(Content::FlushRequest(FlushRequest {
                file_id: self.handle.file_id(),
            }))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        log::debug!("Flushed {}.", self.handle.name());
        Ok(())
    }
}

impl Seek for File {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let next_pos = match pos {
            std::io::SeekFrom::Start(pos) => pos,
            std::io::SeekFrom::End(pos) => {
                let pos = self.end_of_file as i64 + pos;
                if pos < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid seek position",
                    ));
                }
                pos.try_into().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid seek position")
                })?
            }
            std::io::SeekFrom::Current(pos) => {
                let pos = self.pos as i64 + pos;
                if pos < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid seek position",
                    ));
                }
                pos.try_into().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid seek position")
                })?
            }
        };
        if next_pos > self.end_of_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid seek position",
            ));
        }
        Ok(self.pos)
    }
}

#[sync_impl]
impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        File::read(self, buf)
    }
}

#[sync_impl]
impl Write for File {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        File::write(self, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        File::flush(self)
    }
}
