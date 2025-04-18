use super::traits::{SmbTransport, SmbTransportRead, SmbTransportWrite};

#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
use maybe_async::*;
use std::time::Duration;

#[cfg(feature = "async")]
use futures_util::FutureExt;
#[cfg(not(feature = "async"))]
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{tcp, TcpStream},
    select,
};

use binrw::prelude::*;

#[cfg(feature = "async")]
type TcpRead = tcp::OwnedReadHalf;
#[cfg(feature = "async")]
type TcpWrite = tcp::OwnedWriteHalf;

#[cfg(not(feature = "async"))]
type TcpRead = TcpStream;
#[cfg(not(feature = "async"))]
type TcpWrite = TcpStream;
pub struct TcpTransport {
    reader: Option<TcpRead>,
    writer: Option<TcpWrite>,
    timeout: Duration,
}

impl TcpTransport {
    pub fn new(timeout: Duration) -> TcpTransport {
        TcpTransport {
            reader: None,
            writer: None,
            timeout,
        }
    }

    /// Connects to a NetBios server in the specified address with a timeout.
    /// This is the threaded version of [connect](NetBiosClient::connect) -
    /// using the [std::net::TcpStream] as the underlying socket provider.
    #[cfg(not(feature = "async"))]
    fn connect_timeout(&mut self, address: &str) -> crate::Result<TcpStream> {
        use super::utils::TransportUtils;

        if self.timeout == Duration::ZERO {
            log::debug!("Connecting to {}.", address);
            return TcpStream::connect(&address).map_err(Into::into);
        }

        log::debug!("Connecting to {} with timeout {:?}.", address, self.timeout);
        // convert to SocketAddr:
        let address = TransportUtils::parse_socket_address(address)?;
        TcpStream::connect_timeout(&address, self.timeout).map_err(Into::into)
    }

    /// Connects to a NetBios server in the specified address with a timeout.
    /// This is the async version of [connect](NetBiosClient::connect) -
    /// using the [tokio::net::TcpStream] as the underlying socket provider.
    #[cfg(feature = "async")]
    async fn connect_timeout(&mut self, address: &str) -> crate::Result<TcpStream> {
        if self.timeout == Duration::ZERO {
            log::debug!("Connecting to {}.", address);
            return TcpStream::connect(&address).await.map_err(Into::into);
        }

        select! {
            res = TcpStream::connect(&address) => res.map_err(Into::into),
            _ = tokio::time::sleep(self.timeout) => Err(crate::Error::OperationTimeout(format!("Tcp connect to {}", address), self.timeout)),
        }
    }

    /// Async implementation of split socket to read and write halves.
    #[cfg(feature = "async")]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let (r, w) = socket.into_split();
        (r, w)
    }

    /// Sync implementation of split socket to read and write halves.
    #[cfg(not(feature = "async"))]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let rsocket = socket.try_clone().unwrap();
        let wsocket = socket;

        (rsocket, wsocket)
    }

    /// For synchronous implementations, gets the read timeout for the connection.
    #[cfg(not(feature = "async"))]
    pub fn read_timeout(&self) -> crate::Result<Option<std::time::Duration>> {
        self.reader
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .read_timeout()
            .map_err(|e| e.into())
    }

    /// Maps a TCP error to a crate error.
    /// Connection aborts and unexpected EOFs are mapped to [Error::NotConnected].
    #[inline]
    fn map_tcp_error(e: io::Error) -> crate::Error {
        if e.kind() == io::ErrorKind::ConnectionAborted || e.kind() == io::ErrorKind::UnexpectedEof
        {
            log::error!(
                "Got IO error: {} -- Connection Error, notify NotConnected!",
                e
            );
            return crate::Error::NotConnected;
        }
        if e.kind() == io::ErrorKind::WouldBlock {
            log::trace!("Got IO error: {} -- with ErrorKind::WouldBlock.", e);
        } else {
            log::error!("Got IO error: {} -- Mapping to IO error.", e);
        }
        e.into()
    }

    #[maybe_async]
    #[inline]
    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()> {
        let reader = self.reader.as_mut().ok_or(crate::Error::NotConnected)?;
        log::trace!("Reading {} bytes.", out_buf.len());
        reader
            .read_exact(out_buf)
            .await
            .map_err(Self::map_tcp_error)?;
        log::trace!("Read {} bytes OK.", out_buf.len());
        Ok(())
    }

    #[maybe_async::maybe_async]
    #[inline]
    async fn send_raw(&mut self, message: &[u8]) -> crate::Result<()> {
        let writer = self.writer.as_mut().ok_or(crate::Error::NotConnected)?;
        writer
            .write_all(message)
            .await
            .map_err(Self::map_tcp_error)?;
        Ok(())
    }

    #[maybe_async::maybe_async]
    #[inline]
    async fn do_connect(&mut self, address: &str) -> crate::Result<()> {
        let socket = self.connect_timeout(address).await?;
        let (r, w) = Self::split_socket(socket);
        self.reader = Some(r);
        self.writer = Some(w);
        Ok(())
    }
}

impl SmbTransport for TcpTransport {
    #[cfg(feature = "async")]
    fn connect<'a>(&'a mut self, address: &'a str) -> BoxFuture<'a, crate::Result<()>> {
        self.do_connect(address).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn connect(&mut self, address: &str) -> crate::Result<()> {
        self.do_connect(address)
    }

    fn split(
        self: Box<Self>,
    ) -> crate::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        Ok((
            Box::new(Self {
                reader: self.reader,
                writer: None,
                timeout: self.timeout,
            }),
            Box::new(Self {
                reader: None,
                writer: self.writer,
                timeout: self.timeout,
            }),
        ))
    }
}

impl SmbTransportWrite for TcpTransport {
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.send_raw(buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> crate::Result<()> {
        self.send_raw(buf)
    }
}

impl SmbTransportRead for TcpTransport {
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, crate::Result<()>> {
        self.receive_exact(out_buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> crate::Result<()> {
        self.receive_exact(out_buf)
    }

    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> crate::Result<()> {
        self.reader
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.into())
    }
}
