use std::{error::Error, io::Cursor};

use binrw::prelude::*;
use binrw::io::TakeSeekExt;
use crate::pos_marker_3byte::PosMarker3Byte;

use super::{smb1, smb2};

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct NetBiosTcpMessage {
    #[bw(calc = NetBiosTcpMessageHeader::default())]
    pub header: NetBiosTcpMessageHeader,
    // use stream_protocol_length to determine the length of the stream_protocol:
    #[br(map_stream = |s| s.take_seek(header.stream_protocol_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker3Byte::write_and_fill_size, args(&header.stream_protocol_length))]
    pub message: Vec<u8>
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
    pub fn build(message: NetBiosMessageContent) -> Result<NetBiosTcpMessage, Box<dyn Error>> {
        let mut msg_data = Cursor::new(Vec::new());
        message.write(&mut msg_data)?;
        Ok(NetBiosTcpMessage {
            message: msg_data.into_inner()
        })
    }

    pub fn from_header_and_data(header: NetBiosTcpMessageHeader, data: &mut [u8]) -> Result<NetBiosMessageContent, Box<dyn std::error::Error>> {
        assert!(header.stream_protocol_length.value as usize == data.len());
        Ok(NetBiosMessageContent::read(&mut Cursor::new(data))?)
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
pub enum NetBiosMessageContent {
    SMB2Message(smb2::message::SMB2Message),
    SMB1Message(smb1::SMB1NegotiateMessage)
}