use std::{
    io::{Read, Write},
    net::TcpStream,
};

use binrw::io::NoSeek;
use binrw::prelude::*;

use crate::packets::netbios::{NetBiosMessageContent, NetBiosTcpMessage, NetBiosTcpMessageHeader};

pub struct NetBiosClient {
    connection: Option<TcpStream>,
}

impl NetBiosClient {
    pub fn new() -> NetBiosClient {
        NetBiosClient { connection: None }
    }

    /// Connects to a NetBios server in the specified address.
    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.connection = Some(TcpStream::connect(address)?);
        Ok(())
    }

    /// Sends a NetBios message.
    pub fn send(&mut self, data: NetBiosMessageContent) -> Result<(), Box<dyn std::error::Error>> {
        let raw_message = NetBiosTcpMessage::from_content(&data)?;
        self.send_raw(raw_message)
    }

    /// Sends a raw byte array of a NetBios message.
    pub fn send_raw(&mut self, data: NetBiosTcpMessage) -> Result<(), Box<dyn std::error::Error>> {
        // TODO(?): assert data is a valid and not-too-large NetBios message.
        self.connection
            .as_ref()
            .ok_or("NetBiosClient is not connected")?
            .write_all(&data.to_bytes()?)?;

        Ok(())
    }

    // Recieves and parses a NetBios message header, without parsing the message data.
    pub fn recieve_bytes(&mut self) -> Result<NetBiosTcpMessage, Box<dyn std::error::Error>> {
        let mut tcp = self
            .connection
            .as_ref()
            .ok_or("NetBiosClient is not connected")?;

        // Recieve header.
        let header_receiver = &mut NoSeek::new(&mut tcp);
        let header = NetBiosTcpMessageHeader::read(header_receiver)?;
        if header.stream_protocol_length.value > 2u32.pow(3 * 8) - 1 {
            return Err("Stream protocol length is too large".into());
        }

        // Recieve message data.
        let mut data = vec![0; header.stream_protocol_length.value as usize];
        tcp.read_exact(&mut data)?;

        Ok(NetBiosTcpMessage { content: data })
    }
}
