use maybe_async::*;
use std::{io::Cursor, time::Duration};

#[cfg(feature = "sync")]
use std::{
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{tcp, TcpStream},
    select,
};

use binrw::prelude::*;

use crate::packets::netbios::{NetBiosMessageContent, NetBiosTcpMessage, NetBiosTcpMessageHeader};

#[cfg(feature = "async")]
type TcpRead = tcp::OwnedReadHalf;
#[cfg(feature = "async")]
type TcpWrite = tcp::OwnedWriteHalf;

#[cfg(feature = "sync")]
type TcpRead = TcpStream;
#[cfg(feature = "sync")]
type TcpWrite = TcpStream;

/// A (very) simple NETBIOS client.
///
/// This client is NOT thread-safe, and should only be used for SMB wraaping.
///
/// Use [connect](NetBiosClient::connect), [send](NetBiosClient::send),
/// and [receive_bytes](NetBiosClient::received_bytes) to interact with a server.

#[derive(Debug)]
pub struct NetBiosClient {
    reader: Option<TcpRead>,
    writer: Option<TcpWrite>,
    timeout: Option<Duration>,
}

impl NetBiosClient {
    /// Creates a new NetBios client with an optional timeout.
    pub fn new(timeout: Option<Duration>) -> NetBiosClient {
        NetBiosClient {
            reader: None,
            writer: None,
            timeout,
        }
    }

    /// Connects to a NetBios server in the specified address.
    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> crate::Result<()> {
        let socket = self.connect_timeout(address).await?;
        let (r, w) = Self::split_socket(socket);
        self.reader = Some(r);
        self.writer = Some(w);
        Ok(())
    }

    /// Connects to a NetBios server in the specified address with a timeout.
    /// This is the threaded version of [connect](NetBiosClient::connect) -
    /// using the [std::net::TcpStream] as the underlying socket provider.
    #[cfg(feature = "sync")]
    fn connect_timeout(&mut self, address: &str) -> crate::Result<TcpStream> {
        if let Some(t) = self.timeout {
            log::debug!("Connecting to {} with timeout {:?}.", address, t);
            // convert to SocketAddr:
            let address = address
                .to_socket_addrs()?
                .next()
                .ok_or(crate::Error::InvalidAddress(address.to_string()))?;
            TcpStream::connect_timeout(&address, t).map_err(Into::into)
        } else {
            log::debug!("Connecting to {}.", address);
            TcpStream::connect(&address).map_err(Into::into)
        }
    }

    /// Connects to a NetBios server in the specified address with a timeout.
    /// This is the async version of [connect](NetBiosClient::connect) -
    /// using the [tokio::net::TcpStream] as the underlying socket provider.
    #[cfg(feature = "async")]
    async fn connect_timeout(&mut self, address: &str) -> crate::Result<TcpStream> {
        if let None = self.timeout {
            log::debug!("Connecting to {}.", address);
            return TcpStream::connect(&address).await.map_err(Into::into);
        }

        select! {
            res = TcpStream::connect(&address) => res.map_err(Into::into),
            _ = tokio::time::sleep(self.timeout.unwrap()) => Err(crate::Error::OperationTimeout("Tcp connect".to_string(), self.timeout.unwrap())),
        }
    }
    /// Disconnects the client, if not already disconnected.
    pub fn disconnect(&mut self) {
        self.reader.take();
        self.writer.take();
    }

    /// Sends a NetBios message.
    #[maybe_async]
    pub async fn send(&mut self, data: NetBiosMessageContent) -> crate::Result<()> {
        let raw_message = NetBiosTcpMessage::from_content(&data)?;
        Ok(self.send_raw(raw_message).await?)
    }

    /// Sends a raw byte array of a NetBios message.
    #[maybe_async]
    pub async fn send_raw(&mut self, data: NetBiosTcpMessage) -> crate::Result<()> {
        log::trace!("Sending message of size {}.", data.content.len());
        Self::write_all(
            self.writer.as_mut().ok_or(crate::Error::NotConnected)?,
            &data.to_bytes()?,
        )
        .await?;

        Ok(())
    }

    // Receiveds and parses a NetBios message header, without parsing the message data.
    #[maybe_async]
    pub async fn received_bytes(&mut self) -> crate::Result<NetBiosTcpMessage> {
        let tcp = self.reader.as_mut().ok_or(crate::Error::NotConnected)?;

        // Received header.
        let mut header_data = vec![0; NetBiosTcpMessageHeader::SIZE];
        Self::read_exact(tcp, &mut header_data).await?;
        let header = NetBiosTcpMessageHeader::read(&mut Cursor::new(header_data))?;

        if header.stream_protocol_length.value > 2u32.pow(3 * 8) - 1 {
            return Err(crate::Error::InvalidMessage("Message too large.".into()));
        }

        // Received message data.
        let mut data = vec![0; header.stream_protocol_length.value as usize];
        Self::read_exact(tcp, &mut data).await?;

        Ok(NetBiosTcpMessage { content: data })
    }

    /// For synchronous implementations, sets the read timeout for the connection.
    /// This is useful when polling for messages.
    #[cfg(feature = "sync")]
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> crate::Result<()> {
        if !self.can_read() {
            return Err(crate::Error::NotConnected);
        }
        self.reader
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .set_read_timeout(timeout)
            .map_err(|e| e.into())
    }

    /// For synchronous implementations, gets the read timeout for the connection.
    #[cfg(feature = "sync")]
    pub fn read_timeout(&self) -> crate::Result<Option<std::time::Duration>> {
        if !self.can_read() {
            return Err(crate::Error::NotConnected);
        }
        self.reader
            .as_ref()
            .ok_or(crate::Error::NotConnected)?
            .read_timeout()
            .map_err(|e| e.into())
    }

    /// Like an old regular read_exact, but with connection abort handling.
    #[maybe_async]
    async fn read_exact(tcp: &mut TcpRead, buf: &mut [u8]) -> crate::Result<()> {
        log::trace!("Reading {} bytes.", buf.len());
        tcp.read_exact(buf).await.map_err(Self::map_tcp_error)?;
        log::trace!("Read {} bytes OK.", buf.len());
        Ok(())
    }

    /// Like an old regular write_all, but with connection abort handling.
    #[maybe_async]
    async fn write_all(tcp: &mut TcpWrite, buf: &[u8]) -> crate::Result<()> {
        tcp.write_all(buf).await.map_err(Self::map_tcp_error)?;
        Ok(())
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

    /// Async implementation of split socket to read and write halves.
    #[cfg(feature = "async")]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let (r, w) = socket.into_split();
        (r, w)
    }

    /// Sync implementation of split socket to read and write halves.
    #[cfg(feature = "sync")]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let rsocket = socket.try_clone().unwrap();
        let wsocket = socket;

        (rsocket, wsocket)
    }

    /// Splits the client into two separate clients:
    /// One for reading, and one for writing,
    /// given that the client has both the reading and writing capabilities.
    pub fn split(self) -> crate::Result<(NetBiosClient, NetBiosClient)> {
        if !self.can_read() || !self.can_write() {
            return Err(crate::Error::InvalidState(
                "Cannot split a non-connected client.".into(),
            ));
        }
        Ok((
            NetBiosClient {
                reader: self.reader,
                writer: None,
                timeout: self.timeout,
            },
            NetBiosClient {
                reader: None,
                writer: self.writer,
                timeout: self.timeout,
            },
        ))
    }

    /// Checks if the client can read.
    pub fn can_read(&self) -> bool {
        self.reader.is_some()
    }

    pub fn can_write(&self) -> bool {
        self.writer.is_some()
    }
}
