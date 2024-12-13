use std::{io::{Read, Write}, net::TcpStream};

use binrw::prelude::*;
use binrw::io::NoSeek;

use crate::packets::netbios::{NetBiosTcpMessage, NetBiosTcpMessageContent, NetBiosTcpMessageHeader};

pub struct NetBiosClient {
    session: Option<TcpStream>
}

impl NetBiosClient {
    pub fn new() -> NetBiosClient {
        NetBiosClient {
            session: None
        }
    }

    pub fn connect(&mut self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.session = Some(TcpStream::connect(address)?);
        Ok(())
    }

    pub fn send(&mut self, data: NetBiosTcpMessageContent) -> Result<(), Box<dyn std::error::Error>> {
        let netbios_message = NetBiosTcpMessage::new(data);
        let mut netbios_message_bytes = std::io::Cursor::new(Vec::new());
        netbios_message.write(&mut netbios_message_bytes)?;
        self.session.as_ref()
            .ok_or("NetBiosClient is not connected")?
            .write_all(&netbios_message_bytes.into_inner())?;

        Ok(())
    }

    pub fn receive(&mut self) -> Result<NetBiosTcpMessage, Box<dyn std::error::Error>> {
        let mut tcp = self.session.as_ref()
            .ok_or("NetBiosClient is not connected")?;
        
        // 1. Recieve header.
        let header_receiver = &mut NoSeek::new(&mut tcp);
        let header = NetBiosTcpMessageHeader::read(header_receiver)?;
        if header.stream_protocol_length.value > 4096 {
            return Err("Stream protocol length is too large".into());
        }

        // 2. Recieve message data.
        let mut message_data = vec![0; header.stream_protocol_length.value as usize];
        tcp.read_exact(&mut message_data)?;
        
        // 3. Parse message data.
        NetBiosTcpMessage::from_header_and_data(header, &mut message_data)
    }
}