use crate::packets::security::SecurityDescriptor;

use super::*;
use std::io::prelude::*;

pub struct File {
    pub handle: ResourceHandle,

    pos: u64,
    dirty: bool,

    access: FileAccessMask,
    end_of_file: u64,

    file_type: ShareType,
}

/// The `File` struct represents an opened file on the server.
/// Do not create it directly, but via Tree
impl File {
    pub fn new(
        handle: ResourceHandle,
        access: FileAccessMask,
        end_of_file: u64,
        file_type: ShareType,
    ) -> Self {
        File {
            handle,
            pos: 0,
            dirty: false,
            access,
            end_of_file,
            file_type,
        }
    }

    pub fn end_of_file(&self) -> u64 {
        self.end_of_file
    }

    pub fn access(&self) -> FileAccessMask {
        self.access
    }

    #[maybe_async]
    pub async fn query_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileInfoValue,
    {
        let response = self
            .handle
            .send_receive(Content::QueryInfoRequest(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(T::CLASS_ID),
                output_buffer_length: 1024,
                additional_information: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
                data: GetInfoRequestData::None(()),
            }))
            .await?;
        let query_info_response = response.message.content.to_queryinforesponse()?;
        let result = query_info_response
            .parse(InfoType::File)?
            .unwrap_file()
            .parse(T::CLASS_ID)?;
        Ok(result.try_into()?)
    }

    #[maybe_async]
    pub async fn query_security_info(&self) -> crate::Result<SecurityDescriptor> {
        let response = self
            .handle
            .send_receive(Content::QueryInfoRequest(QueryInfoRequest {
                info_type: InfoType::Security,
                info_class: Default::default(),
                output_buffer_length: 1024,
                additional_information: AdditionalInfo::new().with_owner_security_information(true),
                flags: QueryInfoFlags::new(),
                file_id: self.handle.file_id(),
                data: GetInfoRequestData::None(()),
            }))
            .await?;
        let query_info_response = response.message.content.to_queryinforesponse()?;
        let result = query_info_response
            .parse(InfoType::Security)?
            .unwrap_security();
        Ok(result)
    }

    #[maybe_async]
    pub async fn set_file_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileInfoValue,
    {
        let set_file_info: SetFileInfo = info.into();
        let data = SetInfoData::from(RawSetInfoData::from(set_file_info))
            .to_req(T::CLASS_ID, self.handle.file_id());
        let response = self
            .handle
            .send_receive(Content::SetInfoRequest(data))
            .await?;
        let _response = response.message.content.to_setinforesponse()?;
        Ok(())
    }

    /// Read a block of data from an opened file.
    /// # Arguments
    /// * `buf` - The buffer to read the data into. A maximum of `buf.len()` bytes will be read.
    /// * `pos` - The offset in the file to read from.
    /// * `unbuffered` - Whether to try using unbuffered I/O (if supported by the server).
    /// # Returns
    /// The number of bytes read, up to `buf.len()`.
    #[maybe_async]
    pub async fn read_block(
        &self,
        buf: &mut [u8],
        pos: u64,
        unbuffered: bool,
    ) -> std::io::Result<usize> {
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
        if pos >= self.end_of_file {
            return Ok(0);
        }

        log::debug!(
            "Reading up to {} bytes at offset {} from {}",
            buf.len(),
            pos,
            self.handle.name()
        );

        let mut flags = ReadFlags::new();
        if self.handle.conn_info.config.compression_enabled
            && self.handle.conn_info.dialect.supports_compression()
        {
            flags.set_read_compressed(true);
        }

        if unbuffered && self.handle.conn_info.negotiation.dialect_rev >= Dialect::Smb0302 {
            flags.set_read_unbuffered(true);
        }

        let response = self
            .handle
            .send_receive(Content::ReadRequest(ReadRequest {
                padding: 0,
                flags,
                length: buf.len() as u32,
                offset: pos,
                file_id: self.handle.file_id(),
                minimum_count: 1,
            }))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let content = response
            .message
            .content
            .to_readresponse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let actual_read_length = content.buffer.len();
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

        let content = response
            .message
            .content
            .to_writeresponse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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

#[cfg(feature = "sync")]
impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read_length = File::read_block(self, buf, self.pos, false)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        self.pos += read_length as u64;
        Ok(read_length)
    }
}

#[cfg(feature = "sync")]
impl Write for File {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        File::write(self, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        File::flush(self)
    }
}
