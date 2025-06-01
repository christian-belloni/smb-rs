use std::sync::Arc;

use crate::sync_helpers::*;
use maybe_async::*;
#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait ReadAt {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, std::io::Error>;
}

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait WriteAt {
    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize, std::io::Error>;
}

pub trait GetLen {
    fn get_len(&self) -> u64;
}

#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait SetLen {
    async fn set_len(&mut self, len: u64) -> Result<(), std::io::Error>;
}

mod impls {
    use super::*;
    #[cfg(not(feature = "async"))]
    use std::io::{Read, Seek, Write};
    #[cfg(feature = "async")]
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

    #[cfg(feature = "async")]
    pub trait ReadSeek: AsyncRead + AsyncSeek + Unpin {}
    #[cfg(not(feature = "async"))]
    pub trait ReadSeek: Read + Seek {}
    impl<F: ReadSeek> ReadAt for Arc<Mutex<F>> {
        #[maybe_async]
        async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, std::io::Error> {
            let mut reader = self.lock().await.or_else(|e| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
            reader.seek(std::io::SeekFrom::Start(offset)).await?;
            reader.read(buf).await
        }
    }

    #[cfg(feature = "async")]
    pub trait WriteSeek: AsyncWrite + AsyncSeek + Unpin {}
    #[cfg(not(feature = "async"))]
    pub trait WriteSeek: Write + Seek {}
    impl<F: WriteSeek> WriteAt for Arc<Mutex<F>> {
        #[maybe_async]
        async fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize, std::io::Error> {
            let mut writer = self.lock().await.or_else(|e| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
            writer.seek(std::io::SeekFrom::Start(offset)).await?;
            writer.write(buf).await
        }
    }
}

#[maybe_async]
pub async fn copy<F: ReadAt + GetLen, T: WriteAt + SetLen>(
    from: &F,
    to: &mut T,
) -> Result<(), std::io::Error> {
    let file_length = from.get_len();
    to.set_len(file_length).await?;

    let mut buf = vec![0u8; 32768];
    from.read_at(&mut buf, 0).await?;
    to.write_at(&buf, 0).await?;
    Ok(())
}
