use std::{error::Error, io::{Cursor, SeekFrom}, vec};

use binrw::{
    binwrite, helpers::{read_u24, write_u24}, BinRead, BinResult, BinWrite, NullWideString, PosValue
};

mod pos_marker;
use pos_marker::PosMarker;

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16), big)]
enum SMBCommand {
    Negotiate = 00,
    SessionSetup = 01,
    Logoff = 02,
    TreeConnect = 03,
    TreeDisconnect = 04,
    Create = 05,
    Close = 06,
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
#[brw(big)]
#[brw(magic(b"\xfeSMB"))]
struct SMB2MessageHeader {
    structure_size: u16,
    credit_charge: u16,
    status: u32,
    command: SMBCommand,
    credit_request: u16,
    flags: u32,
    next_command: u32,
    message_id: u64,
    reserved: u32,
    tree_id: u32,
    session_id: u64,
    signature: u128
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16), little)]
enum SMBDialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct SMBNegotiateContext {
    // The entire context is 8-byte aligned.
    #[brw(align_before = 8)]
    context_type: SMBNegotiateContextType,
    data_length: u16,
    reserved: u32,
    #[br(args(&context_type))]
    data: SMBNegotiateContextValue
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16), little)]
enum SMBNegotiateContextType {
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    TransportCapabilities = 0x0006,
    RdmaTransformCapabilities = 0x0007,
    SigningCapabilities = 0x0008,
    ContextTypeReserved = 0x0100,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(import(context_type: &SMBNegotiateContextType))]
enum SMBNegotiateContextValue {
    #[br(pre_assert(context_type == &SMBNegotiateContextType::PreauthIntegrityCapabilities))]
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::EncryptionCapabilities))]
    EncryptionCapabilities(EncryptionCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::CompressionCapabilities))]
    CompressionCapabilities(CompressionCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::NetnameNegotiateContextId))]
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::TransportCapabilities))]
    TransportCapabilities(TransportCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::RdmaTransformCapabilities))]
    RdmaTransformCapabilities(RdmaTransformCapabilities),
    #[br(pre_assert(context_type == &SMBNegotiateContextType::SigningCapabilities))]
    SigningCapabilities(SigningCapabilities)
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct PreauthIntegrityCapabilities {
    hash_algorithm_count: u16,
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    hash_algorithms: Vec<u16>,
    #[br(count = salt_length)]
    salt: Vec<u8>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct EncryptionCapabilities {
    cipher_count: u16,
    #[br(count = cipher_count)]
    ciphers: Vec<u16>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct CompressionCapabilities {
    compression_algorithm_count: u16,
    padding: u16,
    flags: u32,
    #[br(count = compression_algorithm_count)]
    compression_algorithms: Vec<u16>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct NetnameNegotiateContextId {
    netname: NullWideString
}


#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct TransportCapabilities {
    flags: u32
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct RdmaTransformCapabilities {
    transform_count: u16,
    reserved1: u16,
    reserved2: u32,
    #[br(count = transform_count)]
    transforms: Vec<u16>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct SigningCapabilities {
    signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count)]
    signing_algorithms: Vec<u16>
}

#[binrw::writer(writer, endian)]
fn write_from_current_position(value: &u32, offset: u32) -> BinResult<()> {
    let value = writer.stream_position().unwrap() as u32 + offset;
    return value.write_options(writer,endian,());
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
struct SMBNegotiateRequest {
    structure_size: u16,
    dialect_count: u16,
    security_mode: u16,
    reserved: u16,
    capabilities: u32,
    client_guid: u128,
    // TODO: The 3 fields below are possibly a union in older versions of SMB.
    negotiate_context_offset: PosMarker<u32>,
    negotiate_context_count: u16,
    reserved2: u16,
    #[br(count = dialect_count)]
    dialects: Vec<SMBDialect>,
    // Only on SMB 3.1.1 we have negotiate contexts.
    #[bw(write_with = PosMarker::fill, args(&negotiate_context_offset))]
    negotiate_context_list_start: PosValue<()>,
    #[brw(if(dialects.contains(&SMBDialect::Smb0311)))]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.pos.get() as u64))]
    negotiate_context_list: Option<Vec<SMBNegotiateContext>>
}

#[derive(BinRead, BinWrite, Debug)]
#[br(import(smb_command: &SMBCommand))]
enum SMBMessageContent {
    #[br(pre_assert(smb_command == &SMBCommand::Negotiate))]
    SMBNegotiateRequest(SMBNegotiateRequest),
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
struct SMB2Message {
    header: SMB2MessageHeader,
    #[br(args(&header.command))]
    content: SMBMessageContent
}

impl SMB2Message {
    fn build() -> SMB2Message {
        SMB2Message {
            header: SMB2MessageHeader {
                structure_size: 64,
                credit_charge: 0,
                status: 0,
                command: SMBCommand::Negotiate,
                credit_request: 0,
                flags: 0,
                next_command: 0,
                message_id: 1,
                reserved: 0,
                tree_id: 0,
                session_id: 0,
                signature: 0
            },
            content: SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest {
                structure_size: 0x24,
                dialect_count: 5,
                security_mode: 0x1,
                reserved: 0,
                capabilities: 0x7f,
                client_guid: 0xf760d952a6b7ef118b78000c29801682,
                negotiate_context_count: 0,
                reserved2: 0,
                dialects: vec![
                    SMBDialect::Smb0202,
                    SMBDialect::Smb021,
                    SMBDialect::Smb030,
                    SMBDialect::Smb0302,
                    SMBDialect::Smb0311
                ],
                negotiate_context_list: Some(vec![])
            })
        }
    }
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
        0x00, 0x00, 0x01, 0x14, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0xf7, 0x60, 0xd9, 0x52, 0xa6, 0xb7, 0xef, 0x11, 0x8b, 0x78, 0x00, 0x0c, 0x29, 0x80, 0x16, 0x82, 0x70, 0x00, 0x00, 0x00, 
        0x06, 0x00, 
        0x00, 0x00, 0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03, 0x00, 0x00, 

        0x01, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0xd2, 0x23, 0xe6, 0xe1, 0x0b, 0xe1, 0x77, 0x81, 0x04, 0xb3, 0xa8, 0xcf, 0x3b, 0xaa, 0x57, 0x90, 0x22, 0x28, 0x4e, 0x23, 0x59, 0x7f, 0xd7, 0xb3, 0x4c, 0xf4, 0x8f, 0xbc, 0xa5, 0x26, 0x76, 0x97, 0x00, 0x00, 
        0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x03, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00,
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x32, 0x00, 0x37, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00
    ];

    let packet = NetBiosTcpMessage::read(&mut Cursor::new(raw_packet));
    let mut message_cursor = Cursor::new(packet?.message);
    _ = dbg!(SMB2Message::read(&mut message_cursor));

    let mut writer = Cursor::new(Vec::new());
    SMB2Message::build().write(&mut writer)?;
    
    dbg!(writer.into_inner());

    Ok(())
}
