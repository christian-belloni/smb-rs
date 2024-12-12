use std::{default, error::Error, io::{Cursor, Read, SeekFrom, Write}, net::TcpStream, vec};

use binrw::{
    binwrite, helpers::{read_u24, until_eof, write_u24}, BinRead, BinResult, BinWrite, NullString, NullWideString, PosValue
};

use binrw::io::TakeSeekExt;

mod pos_marker;
use pos_marker::PosMarker;
use rand::Rng;

fn pos_value_default<T: default::Default>() -> PosValue<T> {
    PosValue {
        pos: u64::default(),
        val: T::default()
    }
}

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
#[brw(little)]
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

// u16 enum hash algorithms binrw 0x01 is sha512.
#[derive(BinRead, BinWrite, Debug)]
#[brw(little, repr(u16))]
enum HashAlgorithm {
    Sha512 = 0x01
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
struct PreauthIntegrityCapabilities {
    hash_algorithm_count: u16,
    #[bw(try_calc(u16::try_from(salt.len())))]
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    hash_algorithms: Vec<HashAlgorithm>,
    #[br(count = salt_length)]
    salt: Vec<u8>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
struct EncryptionCapabilities {
    cipher_count: u16,
    #[br(count = cipher_count)]
    ciphers: Vec<EncryptionCapabilitiesCipher>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, repr(u16))]
enum EncryptionCapabilitiesCipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004
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
    signing_algorithms: Vec<SigningAlgorithmId>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, repr(u16))]
enum SigningAlgorithmId {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002
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
    #[bw(calc = 0x24)]
    #[br(assert(structure_size == 0x24))]
    structure_size: u16,
    #[bw(try_calc(u16::try_from(dialects.len())))]
    dialect_count: u16,
    security_mode: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
    capabilities: u32,
    client_guid: u128,
    // TODO: The 3 fields below are possibly a union in older versions of SMB.
    negotiate_context_offset: PosMarker<u32>,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    negotiate_context_count: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    #[br(count = dialect_count)]
    dialects: Vec<SMBDialect>,
    // Only on SMB 3.1.1 we have negotiate contexts.
    // Align to 8 bytes.
    // #[brw(align_before = 8)]
    #[brw(if(dialects.contains(&SMBDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&negotiate_context_offset))]
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


#[binrw::binrw]
#[derive(Debug)]
#[brw(little, magic(b"\xffSMB"))]
struct SMB1NegotiateMessage {
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
    #[bw(calc = 0)]
    word_count: u8,
    byte_count: u16,
    #[br(map_stream = |s| s.take_seek(byte_count.into()), parse_with = until_eof)]
    dialects: Vec<Smb1Dialect>
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(little, magic(b"\x02"))]
struct Smb1Dialect {
    name: NullString
}

/* SMB1 Header:
UCHAR  Command;
   SMB_ERROR Status;
   UCHAR  Flags;
   USHORT Flags2;
   USHORT PIDHigh;
   UCHAR  SecurityFeatures[8];
   USHORT Reserved;
   USHORT TID;
   USHORT PIDLow;
   USHORT UID;
   USHORT MID; 
Negotiate message conten:
SMB_Parameters
   {
   UCHAR  WordCount;
   }
 SMB_Data
   {
   USHORT ByteCount;
   Bytes
     {
     UCHAR Dialects[];
     }
   }
   */

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
                reserved: 0x0000feff,
                tree_id: 0,
                session_id: 0,
                signature: 0
            },
            content: SMBMessageContent::SMBNegotiateRequest(SMBNegotiateRequest {
                security_mode: 0x1,
                capabilities: 0x7f,
                client_guid: rand::rngs::OsRng.gen(),
                dialects: vec![
                    SMBDialect::Smb0202,
                    SMBDialect::Smb021,
                    SMBDialect::Smb030,
                    SMBDialect::Smb0302,
                    SMBDialect::Smb0311
                ],
                negotiate_context_list: Some(vec![
                    SMBNegotiateContext {
                        context_type: SMBNegotiateContextType::PreauthIntegrityCapabilities,
                        data_length: 38,
                        reserved: 0,
                        data: SMBNegotiateContextValue::PreauthIntegrityCapabilities(
                            PreauthIntegrityCapabilities {
                                hash_algorithm_count: 1,
                                hash_algorithms: vec![HashAlgorithm::Sha512],
                                salt: (0..32).map(|_| rand::random::<u8>()).collect()
                            }
                        )
                    },
                    SMBNegotiateContext {
                        context_type: SMBNegotiateContextType::EncryptionCapabilities,
                        data_length: 10,
                        reserved: 0,
                        data: SMBNegotiateContextValue::EncryptionCapabilities(
                            EncryptionCapabilities {
                                cipher_count: 4,
                                ciphers: vec![
                                    EncryptionCapabilitiesCipher::Aes128Ccm,
                                    EncryptionCapabilitiesCipher::Aes128Gcm,
                                    EncryptionCapabilitiesCipher::Aes256Ccm,
                                    EncryptionCapabilitiesCipher::Aes256Gcm
                                ]
                            }
                        )
                    },
                    SMBNegotiateContext {
                        context_type: SMBNegotiateContextType::CompressionCapabilities,
                        data_length: 10,
                        reserved: 0,
                        data: SMBNegotiateContextValue::CompressionCapabilities(
                            CompressionCapabilities {
                                compression_algorithm_count: 1,
                                padding: 0,
                                flags: 0,
                                compression_algorithms: vec![0]
                            }
                        )
                    },
                    SMBNegotiateContext {
                        context_type: SMBNegotiateContextType::SigningCapabilities,
                        data_length: 6,
                        reserved: 0,
                        data: SMBNegotiateContextValue::SigningCapabilities(
                            SigningCapabilities {
                                signing_algorithm_count: 2,
                                signing_algorithms: vec![
                                    SigningAlgorithmId::AesGmac,
                                    SigningAlgorithmId::AesCmac
                                ]
                            }
                        )
                    },
                    SMBNegotiateContext {
                        context_type: SMBNegotiateContextType::NetnameNegotiateContextId,
                        data_length: 12,
                        reserved: 0,
                        data: SMBNegotiateContextValue::NetnameNegotiateContextId(
                            NetnameNegotiateContextId {
                                netname: NullWideString::from("AVIVVM")
                            }
                        )
                    }
                ]),
                negotiate_context_offset: PosMarker::default()
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

    // Well, it appears that you must always do the multi-protocol negotiation dance with Windows.
    let raw_smb1_packet: &[u8] = &[
        0x00, 0x00, 0x00, 0x45, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00, 
    ];

    // parse raw smb1 packet -- first netBiod header, then SMB1NegotiateMessage:
    let mut packet = NetBiosTcpMessage::read(&mut Cursor::new(raw_smb1_packet));
    let mut message_cursor = Cursor::new(packet?.message);
    let smb1 = SMB1NegotiateMessage::read(&mut message_cursor)?;
    println!("{:?}", smb1);
    assert!(smb1.dialects.iter().any(|dialect| dialect.name.to_string() == "SMB 2.002"));

    let packet = NetBiosTcpMessage::read(&mut Cursor::new(raw_packet));
    let mut message_cursor = Cursor::new(packet?.message);
    _ = dbg!(SMB2Message::read(&mut message_cursor));

    let mut writer = Cursor::new(Vec::new());
    SMB2Message::build().write(&mut writer)?;
    
    let output_vec = writer.into_inner();

    // Now try to parse the output:
    let mut reader = Cursor::new(&output_vec);
    let parsed = SMB2Message::read(&mut reader)?;
    println!("{:?}", parsed);

    let mut tcp_connection = TcpStream::connect("172.16.204.128:445")?;

    // first send the raw smb1 packet:
    tcp_connection.write_all(raw_smb1_packet)?;

    // trim last 2 bytes of the output_vec and copy to a new vec:
    let output_vec = output_vec[..output_vec.len()-2].to_vec();
    // Write netbios header first:
    let netbios_message = NetBiosTcpMessage {
        stream_protocol_length: output_vec.len() as u32,
        message: output_vec
    };

    let mut netbios_message_bytes = Cursor::new(Vec::new());
    netbios_message.write(&mut netbios_message_bytes)?;

    tcp_connection.write_all(&netbios_message_bytes.into_inner())?;
    let mut response : Vec<u8>= vec![];
    tcp_connection.read_to_end(&mut response)?;

    Ok(())
}
