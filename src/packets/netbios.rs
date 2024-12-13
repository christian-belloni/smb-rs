use binrw::prelude::*;
use binrw::io::TakeSeekExt;
use crate::pos_marker::PosMarker;

use super::{smb1, smb2};

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct NetBiosTcpMessage {
    header: NetBiosTcpMessageHeader,
    // use stream_protocol_length to determine the length of the stream_protocol:
    #[br(map_stream = |s| s.take_seek(header.stream_protocol_length.value.into()))]
    #[bw(write_with = PosMarker::write_and_fill_size, args(&header.stream_protocol_length))]
    pub message: NetBiosTcpMessageContent
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(big, magic(b"\x00"))]
pub struct NetBiosTcpMessageHeader {
    #[bw(write_with = PosMarker::write_u24)]
    #[br(parse_with = PosMarker::read_u24)]
    stream_protocol_length: PosMarker<u32>,
}

impl Default for NetBiosTcpMessageHeader {
    fn default() -> NetBiosTcpMessageHeader {
        NetBiosTcpMessageHeader {
            stream_protocol_length: PosMarker::default()
        }
    }
}

impl NetBiosTcpMessage {
    pub fn build() -> NetBiosTcpMessage {
        NetBiosTcpMessage {
            header: NetBiosTcpMessageHeader::default(),
            message: NetBiosTcpMessageContent::SMB2Message(smb2::message::SMB2Message::build())
        }
    }
}

#[derive(BinRead, BinWrite, Debug)]
pub enum NetBiosTcpMessageContent {
    SMB2Message(smb2::message::SMB2Message),
    SMB1Message(smb1::SMB1NegotiateMessage)
}