use std::io::Cursor;

use binrw::prelude::*;
use binrw::io::TakeSeekExt;
use crate::pos_marker_3byte::PosMarker3Byte;

use super::{smb1, smb2};

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct NetBiosTcpMessage {
    pub header: NetBiosTcpMessageHeader,
    // use stream_protocol_length to determine the length of the stream_protocol:
    #[br(map_stream = |s| s.take_seek(header.stream_protocol_length.value.into()))]
    #[bw(write_with = PosMarker3Byte::write_and_fill_size, args(&header.stream_protocol_length))]
    pub message: NetBiosTcpMessageContent
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(big, magic(b"\x00"))]
pub struct NetBiosTcpMessageHeader {
    pub stream_protocol_length: PosMarker3Byte,
}

impl Default for NetBiosTcpMessageHeader {
    fn default() -> NetBiosTcpMessageHeader {
        NetBiosTcpMessageHeader {
            stream_protocol_length: PosMarker3Byte::default()
        }
    }
}

impl NetBiosTcpMessage {
    pub fn new(message: NetBiosTcpMessageContent) -> NetBiosTcpMessage {
        NetBiosTcpMessage {
            header: NetBiosTcpMessageHeader::default(),
            message
        }
    }

    pub fn from_header_and_data(header: NetBiosTcpMessageHeader, data: &mut [u8]) -> Result<NetBiosTcpMessage, Box<dyn std::error::Error>> {
        Ok(NetBiosTcpMessage {
            header,
            message: NetBiosTcpMessageContent::read(&mut Cursor::new(data))?
        })
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
pub enum NetBiosTcpMessageContent {
    SMB2Message(smb2::message::SMB2Message),
    SMB1Message(smb1::SMB1NegotiateMessage)
}