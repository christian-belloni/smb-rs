use binrw::NullString;

use crate::packets::security::SecurityDescriptor;

use super::*;
#[cfg(feature = "sync")]
use std::io::prelude::*;

/// An opened file on the server.
/// This struct also represents an open named pipe or a printer. use [File::file_type] to
/// determine the type of the share this file belongs to.
///
/// # [std::io] Support
/// The [File] struct also supports the [Read][std::io::Read] and [Write][std::io::Write] traits.
/// Note that both of these traits are blocking, and will block the current thread until the operation is complete.
/// Use [File::read_block] and [File::write_block] for non-blocking operations.
/// The [File] struct also implements the [Seek][std::io::Seek] trait.
/// This allows you to seek to a specific position in the file, combined with the [Read][std::io::Read] and [Write][std::io::Write] traits.
/// Using any of the implemented [std::io] traits mentioned above should have no effect on calling the other, non-blocking methods.
/// Since we would NOT like to call a tokio task from a blocking context, these traits are **NOT** implemented in the async context!
///
/// You may not directly create this struct. Instead, use the [Tree::create][crate::tree::Tree::create] method to gain
/// a proper handle against the server in the shape of a [Resource][crate::resource::Resource], that can be then converted to a [File].
pub struct File {
    handle: ResourceHandle,

    #[cfg(feature = "sync")]
    pos: u64,
    #[cfg(feature = "sync")]
    dirty: bool,

    access: FileAccessMask,
    end_of_file: u64,

    share_type: ShareType,
}

impl File {
    pub fn new(
        handle: ResourceHandle,
        access: FileAccessMask,
        end_of_file: u64,
        file_type: ShareType,
    ) -> Self {
        File {
            handle,
            access,
            end_of_file,
            share_type: file_type,
            #[cfg(feature = "sync")]
            pos: 0,
            #[cfg(feature = "sync")]
            dirty: false,
        }
    }

    /// Returns the end of file position, as reported by the server.
    /// This may change if the file is modified.
    pub fn end_of_file(&self) -> u64 {
        self.end_of_file
    }

    /// Returns the access mask of the file,
    /// when the file was opened.
    pub fn access(&self) -> FileAccessMask {
        self.access
    }

    /// Returns the current share type of the file. See [ShareType] for more details.
    pub fn file_type(&self) -> ShareType {
        self.share_type
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
            .handle
            .query_common(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(T::CLASS_ID),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
                data: GetInfoRequestData::None(()),
            })
            .await?
            .unwrap_file()
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
            .handle
            .query_common(QueryInfoRequest {
                info_type: InfoType::File,
                info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
                data: GetInfoRequestData::EaInfo(GetEaInfoList {
                    values: names
                        .iter()
                        .map(|&s| {
                            FileGetEaInformationInner {
                                ea_name: NullString::from(s),
                            }
                            .into()
                        })
                        .collect(),
                }),
            })
            .await?
            .unwrap_file()
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
            .handle
            .query_common(QueryInfoRequest {
                info_type: InfoType::Security,
                info_class: Default::default(),
                output_buffer_length: 1024,
                additional_info,
                flags: QueryInfoFlags::new(),
                file_id: self.handle.file_id(),
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
            .handle
            .query_common(QueryInfoRequest {
                info_type: InfoType::FileSystem,
                info_class: QueryInfoClass::FileSystem(T::CLASS_ID),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id(),
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
        self.handle
            .set_info_common(
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

        self.handle
            .set_info_common(
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
        self.handle
            .set_info_common(
                info,
                SetInfoClass::Security(Default::default()),
                additional_info,
            )
            .await
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

    /// Write a block of data to an opened file.
    /// # Arguments
    /// * `buf` - The data to write.
    /// * `pos` - The offset in the file to write to.
    /// # Returns
    /// The number of bytes written.
    #[maybe_async]
    pub async fn write_block(&self, buf: &[u8], pos: u64) -> std::io::Result<usize> {
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
            pos,
            self.handle.name()
        );

        let response = self
            .handle
            .send_receive(Content::WriteRequest(WriteRequest {
                offset: pos,
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
        log::debug!(
            "Wrote {} bytes to {}.",
            actual_written_length,
            self.handle.name()
        );
        Ok(actual_written_length)
    }

    /// Sends a flush request to the server to flush the file.
    #[maybe_async]
    pub async fn flush(&self) -> std::io::Result<()> {
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

// Despite being available, seeking means nothing here,
// since it may only be used when calling read/write from the std::io traits.
#[cfg(feature = "sync")]
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
        let written_length = File::write_block(self, buf, self.pos)?;
        self.pos += written_length as u64;
        self.dirty = true;
        Ok(written_length)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        File::flush(self)
    }
}
