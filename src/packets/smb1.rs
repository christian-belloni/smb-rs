use binrw::prelude::*;
use binrw::io::TakeSeekExt;

use crate::pos_marker::PosMarker;

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
#[brw(magic(b"\xffSMB"))]
pub struct SMB1NegotiateMessage {
    #[bw(calc = 0x72)]
    #[br(assert(_command == 0x72))]
    _command: u8,
    status: u32,
    flags: u8,
    flags2: u16,
    #[bw(calc = 0)]
    #[br(assert(_pid_high == 0))]
    _pid_high: u16,
    security_features: [u8; 8],
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = 0xff)]
    _tid: u16,
    #[bw(calc = 1)]
    #[br(assert(_pid_low == 1))]
    _pid_low: u16,
    #[bw(calc = 0xff)]
    _uid: u16,
    #[bw(calc = 1)]
    _mid: u16,
    // word count is always 0x0 according to MS-CIFS.
    #[bw(calc = 0)]
    #[br(assert(_word_count == 0))]
    _word_count: u8,
    byte_count: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(byte_count.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_and_fill_size, args(&byte_count))]
    dialects: Vec<Smb1Dialect>
}

impl SMB1NegotiateMessage {
    pub fn new() -> SMB1NegotiateMessage {
        SMB1NegotiateMessage {
            status: 0,
            flags: 0x08,
            flags2: 0xc801,
            security_features: [0; 8],
            byte_count: PosMarker::default(),
            dialects: vec![
                Smb1Dialect {
                    name: binrw::NullString::from("NT LM 0.12"),
                },
                Smb1Dialect {
                    name: binrw::NullString::from("SMB 2.002"),
                },
                Smb1Dialect {
                    name: binrw::NullString::from("SMB 2.???"),
                },
            ]
        }
    }

    pub fn is_smb2_supported(&self) -> bool {
        self.dialects.iter().any(|d| d.name.to_string() == "SMB 2.002")
    }
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, magic(b"\x02"))]
pub struct Smb1Dialect {
    name: binrw::NullString
}
