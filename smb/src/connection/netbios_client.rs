use maybe_async::*;
use std::io::Cursor;

#[cfg(not(feature = "async"))]
use std::{
    io::{Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use binrw::prelude::*;

use crate::packets::netbios::{NetBiosMessageContent, NetBiosTcpMessage, NetBiosTcpMessageHeader};

pub struct NetBiosClient {
    connection: Option<TcpStream>,
}

impl NetBiosClient {
    pub fn new() -> NetBiosClient {
        NetBiosClient { connection: None }
    }

    #[maybe_async]
    /// Connects to a NetBios server in the specified address.
    pub async fn connect(&mut self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.connection = Some(TcpStream::connect(address).await?);
        Ok(())
    }

    #[maybe_async]
    /// Sends a NetBios message.
    pub async fn send(
        &mut self,
        data: NetBiosMessageContent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let raw_message = NetBiosTcpMessage::from_content(&data)?;
        self.send_raw(raw_message).await
    }

    #[maybe_async]
    /// Sends a raw byte array of a NetBios message.
    pub async fn send_raw(
        &mut self,
        data: NetBiosTcpMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // TODO(?): assert data is a valid and not-too-large NetBios message.
        self.connection
            .as_mut()
            .ok_or("NetBiosClient is not connected")?
            .write_all(&data.to_bytes()?)
            .await?;

        Ok(())
    }

    #[maybe_async]
    // Recieves and parses a NetBios message header, without parsing the message data.
    pub async fn recieve_bytes(&mut self) -> Result<NetBiosTcpMessage, Box<dyn std::error::Error>> {
        let tcp = self
            .connection
            .as_mut()
            .ok_or("NetBiosClient is not connected")?;

        // Recieve header.
        let mut header_data = vec![0; NetBiosTcpMessageHeader::SIZE];
        tcp.read_exact(&mut header_data).await?;
        let header = NetBiosTcpMessageHeader::read(&mut Cursor::new(header_data))?;

        if header.stream_protocol_length.value > 2u32.pow(3 * 8) - 1 {
            return Err("Stream protocol length is too large".into());
        }

        // Recieve message data.
        let mut data = vec![0; header.stream_protocol_length.value as usize];
        tcp.read_exact(&mut data).await?;

        Ok(NetBiosTcpMessage { content: data })
    }
}
