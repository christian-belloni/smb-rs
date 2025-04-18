use std::io::Cursor;

use super::{smb1, smb2};
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
#[brw(big, magic(b"\x00"))]
pub struct SmbTcpMessageHeader {
    #[br(parse_with = binrw::helpers::read_u24)]
    #[bw(write_with = binrw::helpers::write_u24)]
    pub stream_protocol_length: u32,
}

impl SmbTcpMessageHeader {
    /// Size of the header, including the magic number (0x00).
    pub const SIZE: usize = 4;
}

/// Represents a parsed SMB message.
///
/// Use [`SMBMessage::try_from`] to parse a buffer
/// containing an SMB message to this struct.
/// Use [`SMBMessage::try_into`] to convert this struct
/// back to a buffer containing the SMB message.
#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
pub enum SMBMessage {
    SMB2Message(smb2::Message),
    // This is for multi-protocol negotiation purpose ONLY.
    SMB1Message(smb1::SMB1NegotiateMessage),
}

impl TryFrom<&[u8]> for SMBMessage {
    type Error = binrw::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(SMBMessage::read(&mut Cursor::new(value))?)
    }
}

impl TryInto<Vec<u8>> for SMBMessage {
    type Error = binrw::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = Cursor::new(Vec::new());
        self.write(&mut buf)?;
        Ok(buf.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_transport_header_write() {
        let header = SmbTcpMessageHeader {
            stream_protocol_length: 0x123456,
        };
        let mut buf = Vec::new();
        header.write(&mut Cursor::new(&mut buf)).unwrap();
        assert_eq!(&[0x00, 0x12, 0x34, 0x56], &buf.as_ref());
    }

    #[test]
    fn test_transport_header_read() {
        let buf = [0x00, 0x12, 0x34, 0x56];
        let header = SmbTcpMessageHeader::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(header.stream_protocol_length, 0x123456);
    }
}
