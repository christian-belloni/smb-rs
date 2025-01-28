use std::io::Cursor;

use super::binrw_util::prelude::*;
use super::{smb1, smb2};
use binrw::io::TakeSeekExt;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct NetBiosTcpMessage {
    #[bw(calc = NetBiosTcpMessageHeader::default())]
    pub header: NetBiosTcpMessageHeader,
    // use stream_protocol_length to determine the length of the stream_protocol:
    #[br(map_stream = |s| s.take_seek(header.stream_protocol_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker3Byte::write_and_fill_size, args(&header.stream_protocol_length))]
    pub content: Vec<u8>,
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
            stream_protocol_length: PosMarker3Byte::default(),
        }
    }
}

impl NetBiosTcpMessage {
    pub fn parse_content(&self) -> Result<NetBiosMessageContent, Box<dyn std::error::Error>> {
        Ok(NetBiosMessageContent::try_from(self.content.as_slice())?)
    }

    pub fn from_content(
        content: &NetBiosMessageContent,
    ) -> Result<NetBiosTcpMessage, Box<dyn std::error::Error>> {
        let mut content_writer = Cursor::new(vec![]);
        content.write(&mut content_writer)?;
        Self::from_content_bytes(content_writer.into_inner())
    }

    pub fn from_content_bytes(
        content: Vec<u8>,
    ) -> Result<NetBiosTcpMessage, Box<dyn std::error::Error>> {
        Ok(NetBiosTcpMessage { content })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, binrw::Error> {
        let mut msg_data = Cursor::new(Vec::new());
        self.write(&mut msg_data)?;
        Ok(msg_data.into_inner())
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
pub enum NetBiosMessageContent {
    SMB2Message(smb2::message::Message),
    SMB1Message(smb1::SMB1NegotiateMessage),
}

impl TryFrom<&[u8]> for NetBiosMessageContent {
    type Error = binrw::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(NetBiosMessageContent::read(&mut Cursor::new(value))?)
    }
}
