use maybe_async::*;
use std::io::Cursor;

#[cfg(not(feature = "async"))]
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use binrw::prelude::*;

use crate::packets::netbios::{NetBiosMessageContent, NetBiosTcpMessage, NetBiosTcpMessageHeader};

/// A (very) simple NETBIOS client.
///
/// This client is NOT thread-safe, and should only be used for SMB wraaping.
///
/// Use [connect](NetBiosClient::connect), [send](NetBiosClient::send),
/// and [receive_bytes](NetBiosClient::recieve_bytes) to interact with a server.
pub struct NetBiosClient {
    connection: Option<TcpStream>,
}

impl NetBiosClient {
    pub fn new() -> NetBiosClient {
        NetBiosClient { connection: None }
    }

    /// Connects to a NetBios server in the specified address.
    #[maybe_async]
    pub async fn connect(&mut self, address: &str) -> Result<(), io::Error> {
        self.connection = Some(TcpStream::connect(address).await?);
        Ok(())
    }

    /// Sends a NetBios message.
    #[maybe_async]
    pub async fn send(&mut self, data: NetBiosMessageContent) -> Result<(), crate::Error> {
        let raw_message = NetBiosTcpMessage::from_content(&data)?;
        Ok(self.send_raw(raw_message).await?)
    }

    /// Sends a raw byte array of a NetBios message.
    #[maybe_async]
    pub async fn send_raw(&mut self, data: NetBiosTcpMessage) -> Result<(), crate::Error> {
        // TODO(?): assert data is a valid and not-too-large NetBios message.
        self.connection
            .as_mut()
            .ok_or(crate::Error::NotConnected)?
            .write_all(&data.to_bytes()?)
            .await?;

        Ok(())
    }

    // Recieves and parses a NetBios message header, without parsing the message data.
    #[maybe_async]
    pub async fn recieve_bytes(&mut self) -> Result<NetBiosTcpMessage, crate::Error> {
        let tcp = self.connection.as_mut().ok_or(crate::Error::NotConnected)?;

        // Recieve header.
        let mut header_data = vec![0; NetBiosTcpMessageHeader::SIZE];
        tcp.read_exact(&mut header_data).await?;
        let header = NetBiosTcpMessageHeader::read(&mut Cursor::new(header_data))?;

        if header.stream_protocol_length.value > 2u32.pow(3 * 8) - 1 {
            return Err(crate::Error::InvalidMessage("Message too large.".into()));
        }

        // Recieve message data.
        let mut data = vec![0; header.stream_protocol_length.value as usize];
        tcp.read_exact(&mut data).await?;

        Ok(NetBiosTcpMessage { content: data })
    }
}
