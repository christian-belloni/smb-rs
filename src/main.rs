use std::{error::Error, io::Cursor};

use binrw::{
    BinRead, 
    BinWrite,
    helpers::{read_u24, write_u24}
};

#[derive(BinRead, BinWrite, Debug)]
#[brw(repr(u16), little)]
enum SMBCommand {
    Negotiate = 00,
    SessionSetup = 01,
    LOGOFF = 02,
    TreeConnect = 03,
    TreeDisconnect = 04,
    Create = 05,
    Clost = 06,
    Flush = 07,
    Read = 08,
    Write = 09,
    Lock = 0xA,
    Ioctl = 0xB,
    Cancel = 0xC,
    Echo = 0xD,
    QueryDirectory = 0xE,
    ChangeNotify = 0xF,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct SMB2Message {
    protocol_id: u32,
    structure_size: u16,
    credit_charge: u16,
    status: u32,
    command: SMBCommand,
    credit_request: u32,
    flags: u32,
    next_command: u32,
    message_id: u64,
    reserved: u32,
    tree_id: u32,
    session_id: u64,
    signature: u128
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big, magic(b"\x00"))]
struct NetBiosTcpMessage {
    #[bw(write_with = write_u24)]
    #[br(parse_with = read_u24)]
    stream_protocol_length: u32,
    #[br(count = stream_protocol_length)]
    message: Vec<u8>
}

fn main() -> Result<(), Box<dyn Error>> {
    let raw_packet: &[u8] = &[
        0x00, 
        0x00, 0x00, 0x45, 
        0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00
    ];

    let packet = NetBiosTcpMessage::read(&mut Cursor::new(raw_packet));
    dbg!(&packet);

    let mut message_cursor = Cursor::new(packet?.message);
    _ = dbg!(SMB2Message::read(&mut message_cursor));

    Ok(())
}
