use std::{io::{Read, Write}, net::TcpStream};

use binrw::prelude::*;
use binrw::io::NoSeek;

use crate::packets::netbios::{NetBiosTcpMessage, NetBiosMessageContent, NetBiosTcpMessageHeader};

/// Describes an unparsed NetBios message.
pub struct RawNetBiosMessage {
    pub header: NetBiosTcpMessageHeader, 
    pub data: Vec<u8>
}

impl RawNetBiosMessage {
    pub fn parse(&self) -> Result<NetBiosMessageContent, Box<dyn std::error::Error>> {
        assert!(self.header.stream_protocol_length.value == self.data.len() as u32);
        Ok(NetBiosMessageContent::try_from(self.data.as_slice())?)
    }
}


pub struct NetBiosClient {
    session: Option<TcpStream>
}

impl NetBiosClient {
    pub fn new() -> NetBiosClient {
        NetBiosClient {
            session: None
        }
    }

    /// Connects to a NetBios server in the specified address.
    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.session = Some(TcpStream::connect(address)?);
        Ok(())
    }

    /// Sends a NetBios message.
    pub fn send(&mut self, data: NetBiosMessageContent) -> Result<(), Box<dyn std::error::Error>> {
        let netbios_message_bytes: Vec<u8> = NetBiosTcpMessage::build(data)?.to_bytes()?;
        self.send_bytes(&netbios_message_bytes)
    }

    /// Sends a raw byte array of a NetBios message.
    pub fn send_bytes(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        // TODO(?): assert data is a valid and not-too-large NetBios message.
        self.session.as_ref()
            .ok_or("NetBiosClient is not connected")?
            .write_all(data)?;

        Ok(())
    }

    // Recieves and parses a NetBios message header, without parsing the message data.
    pub fn recieve_bytes(&mut self) -> Result<RawNetBiosMessage, Box<dyn std::error::Error>> {
        let mut tcp = self.session.as_ref()
            .ok_or("NetBiosClient is not connected")?;
        
        // Recieve header.
        let header_receiver = &mut NoSeek::new(&mut tcp);
        let header = NetBiosTcpMessageHeader::read(header_receiver)?;
        if header.stream_protocol_length.value > 4096 {
            return Err("Stream protocol length is too large".into());
        }

        // Recieve message data.
        let mut data = vec![0; header.stream_protocol_length.value as usize];
        tcp.read_exact(&mut data)?;

        Ok(RawNetBiosMessage { header, data })
    }
}