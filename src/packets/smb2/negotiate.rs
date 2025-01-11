use binrw::io::{SeekFrom, TakeSeekExt};
use binrw::prelude::*;

use super::super::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct NegotiateRequest {
    #[bw(calc = 0x24)]
    #[br(assert(structure_size == 0x24))]
    structure_size: u16,
    #[bw(try_calc(u16::try_from(dialects.len())))]
    dialect_count: u16,
    pub security_mode: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
    pub capabilities: u32,
    pub client_guid: u128,
    // TODO: The 3 fields below are possibly a union in older versions of SMB.
    negotiate_context_offset: PosMarker<u32>,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    negotiate_context_count: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
    // Only on SMB 3.1.1 we have negotiate contexts.
    // Align to 8 bytes.
    #[brw(if(dialects.contains(&Dialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

impl NegotiateRequest {
    pub fn new(
        client_netname: String,
        client_guid: u128,
        signing_algorithms: Vec<SigningAlgorithmId>,
    ) -> NegotiateRequest {
        NegotiateRequest {
            security_mode: 0x1,
            capabilities: 0x7f,
            client_guid: client_guid,
            dialects: vec![
                Dialect::Smb0202,
                Dialect::Smb021,
                Dialect::Smb030,
                Dialect::Smb0302,
                Dialect::Smb0311,
            ],
            negotiate_context_list: Some(vec![
                NegotiateContext {
                    context_type: NegotiateContextType::PreauthIntegrityCapabilities,
                    data: NegotiateContextValue::PreauthIntegrityCapabilities(
                        PreauthIntegrityCapabilities {
                            hash_algorithms: vec![HashAlgorithm::Sha512],
                            salt: (0..32).map(|_| rand::random::<u8>()).collect(),
                        },
                    ),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::EncryptionCapabilities,
                    data: NegotiateContextValue::EncryptionCapabilities(EncryptionCapabilities {
                        cipher_count: 4,
                        ciphers: vec![
                            EncryptionCapabilitiesCipher::Aes128Ccm,
                            EncryptionCapabilitiesCipher::Aes128Gcm,
                            EncryptionCapabilitiesCipher::Aes256Ccm,
                            EncryptionCapabilitiesCipher::Aes256Gcm,
                        ],
                    }),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::CompressionCapabilities,
                    data: NegotiateContextValue::CompressionCapabilities(CompressionCapabilities {
                        compression_algorithm_count: 1,
                        padding: 0,
                        flags: 0,
                        compression_algorithms: vec![0],
                    }),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::SigningCapabilities,
                    data: NegotiateContextValue::SigningCapabilities(SigningCapabilities {
                        signing_algorithms,
                    }),
                },
                NegotiateContext {
                    context_type: NegotiateContextType::NetnameNegotiateContextId,
                    data: NegotiateContextValue::NetnameNegotiateContextId(
                        NetnameNegotiateContextId {
                            netname: client_netname.into(),
                        },
                    ),
                },
            ]),
            negotiate_context_offset: PosMarker::default(),
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct NegotiateResponse {
    #[br(assert(structure_size == 0x41))]
    #[bw(calc = 0x41)]
    structure_size: u16,
    pub security_mode: u16,
    pub dialect_revision: NegotiateDialect,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    #[br(assert(if dialect_revision == NegotiateDialect::Smb0311 { negotiate_context_count > 0 } else { negotiate_context_count == 0 }))]
    negotiate_context_count: u16,
    pub server_guid: u128,
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: u64,
    pub server_start_time: u64,
    security_buffer_offset: PosMarker<u16>,
    #[bw(try_calc(u16::try_from(buffer.len())))]
    security_buffer_length: u16,
    negotiate_context_offset: PosMarker<u32>,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&security_buffer_offset))]
    pub buffer: Vec<u8>,

    #[brw(if(matches!(dialect_revision, NegotiateDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

impl NegotiateResponse {
    pub fn get_signing_algo(&self) -> Option<SigningAlgorithmId> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts
                .iter()
                .find_map(|context| match &context.context_type {
                    NegotiateContextType::SigningCapabilities => match &context.data {
                        NegotiateContextValue::SigningCapabilities(caps) => {
                            caps.signing_algorithms.first().copied()
                        }
                        _ => None,
                    },
                    _ => None,
                })
        })
    }

    pub fn get_preauth_integrity_algos(&self) -> Option<&Vec<HashAlgorithm>> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts
                .iter()
                .find_map(|context| match &context.context_type {
                    NegotiateContextType::PreauthIntegrityCapabilities => match &context.data {
                        NegotiateContextValue::PreauthIntegrityCapabilities(caps) => {
                            Some(caps.hash_algorithms.as_ref())
                        }
                        _ => None,
                    },
                    _ => None,
                })
        })
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum Dialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311,
}

/// Dialects that may be used in the SMB Negotiate Request.
/// The same as [Dialect] but with a wildcard for SMB 2.0.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum NegotiateDialect {
    Smb0202 = Dialect::Smb0202 as isize,
    Smb021 = Dialect::Smb021 as isize,
    Smb030 = Dialect::Smb030 as isize,
    Smb0302 = Dialect::Smb0302 as isize,
    Smb0311 = Dialect::Smb0311 as isize,
    Smb02Wildcard = 0x02FF,
}

impl TryFrom<NegotiateDialect> for Dialect {
    type Error = &'static str;

    fn try_from(value: NegotiateDialect) -> Result<Self, Self::Error> {
        match value {
            NegotiateDialect::Smb0202 => Ok(Dialect::Smb0202),
            NegotiateDialect::Smb021 => Ok(Dialect::Smb021),
            NegotiateDialect::Smb030 => Ok(Dialect::Smb030),
            NegotiateDialect::Smb0302 => Ok(Dialect::Smb0302),
            NegotiateDialect::Smb0311 => Ok(Dialect::Smb0311),
            _ => {
                Err("Negotiation Response dialect does not match a single, specific, SMB2 dialect!")
            }
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct NegotiateContext {
    // The entire context is 8-byte aligned.
    #[brw(align_before = 8)]
    pub context_type: NegotiateContextType,
    #[bw(calc = PosMarker::default())]
    data_length: PosMarker<u16>,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u32,
    #[br(args(&context_type))]
    #[br(map_stream = |s| s.take_seek(data_length.value as u64))]
    #[bw(write_with = PosMarker::write_and_fill_size, args(&data_length))]
    pub data: NegotiateContextValue,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum NegotiateContextType {
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
#[br(import(context_type: &NegotiateContextType))]
pub enum NegotiateContextValue {
    #[br(pre_assert(context_type == &NegotiateContextType::PreauthIntegrityCapabilities))]
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::EncryptionCapabilities))]
    EncryptionCapabilities(EncryptionCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::CompressionCapabilities))]
    CompressionCapabilities(CompressionCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::NetnameNegotiateContextId))]
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    #[br(pre_assert(context_type == &NegotiateContextType::TransportCapabilities))]
    TransportCapabilities(TransportCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::RdmaTransformCapabilities))]
    RdmaTransformCapabilities(RdmaTransformCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::SigningCapabilities))]
    SigningCapabilities(SigningCapabilities),
}

// u16 enum hash algorithms binrw 0x01 is sha512.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum HashAlgorithm {
    Sha512 = 0x01,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct PreauthIntegrityCapabilities {
    #[bw(try_calc(u16::try_from(hash_algorithms.len())))]
    hash_algorithm_count: u16,
    #[bw(try_calc(u16::try_from(salt.len())))]
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    pub hash_algorithms: Vec<HashAlgorithm>,
    #[br(count = salt_length)]
    pub salt: Vec<u8>,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct EncryptionCapabilities {
    cipher_count: u16,
    #[br(count = cipher_count)]
    ciphers: Vec<EncryptionCapabilitiesCipher>,
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(repr(u16))]
pub enum EncryptionCapabilitiesCipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct CompressionCapabilities {
    compression_algorithm_count: u16,
    padding: u16,
    flags: u32,
    #[br(count = compression_algorithm_count)]
    compression_algorithms: Vec<u16>,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct NetnameNegotiateContextId {
    #[br(parse_with = binrw::helpers::until_eof)]
    netname: SizedWideString,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct TransportCapabilities {
    flags: u32,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct RdmaTransformCapabilities {
    transform_count: u16,
    reserved1: u16,
    reserved2: u32,
    #[br(count = transform_count)]
    transforms: Vec<u16>,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SigningCapabilities {
    #[bw(try_calc(u16::try_from(signing_algorithms.len())))]
    signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count)]
    pub signing_algorithms: Vec<SigningAlgorithmId>,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum SigningAlgorithmId {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002,
}
