use binrw::prelude::*;
use binrw::io::TakeSeekExt;

use crate::pos_marker::PosMarker;

#[binrw::binrw]
#[derive(Debug)]
#[brw(little, magic(b"\xffSMB"))]
pub struct SMB1NegotiateMessage {
    command: u8,
    status: u32,
    flags: u8,
    flags2: u16,
    pid_high: u16,
    security_features: [u8; 8],
    reserved: u16,
    tid: u16,
    pid_low: u16,
    uid: u16,
    mid: u16,
    // word count is always 0x0 according to MS-CIFS.
    #[bw(calc = 0)]
    _word_count: u8,
    byte_count: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(byte_count.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_and_fill_size, args(&byte_count))]
    dialects: Vec<Smb1Dialect>
}

impl SMB1NegotiateMessage {
    pub fn is_smb2_supported(&self) -> bool {
        self.dialects.iter().any(|d| d.name.to_string() == "SMB 2.002")
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, magic(b"\x02"))]
pub struct Smb1Dialect {
    name: binrw::NullString
}
