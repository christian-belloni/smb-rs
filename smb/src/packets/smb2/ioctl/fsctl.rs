//! FSCTL codes and structs.
use binrw::{io::TakeSeekExt, prelude::*, NullWideString};
use modular_bitfield::prelude::*;

use crate::packets::{
    binrw_util::prelude::{FileTime, PosMarker},
    fscc::ChainedItem,
    guid::Guid,
    smb2::{Dialect, NegotiateSecurityMode},
};

use super::common::IoctlRequestContent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsctlCodes {
    DfsGetReferrals = 0x00060194,
    PipePeek = 0x0011400C,
    PipeWait = 0x00110018,
    PipeTransceive = 0x0011C017,
    SrvCopychunk = 0x001440F2,
    SrvEnumerateSnapshots = 0x00144064,
    SrvRequestResumeKey = 0x00140078,
    SrvReadHash = 0x001441bb,
    SrvCopychunkWrite = 0x001480F2,
    LmrRequestResiliency = 0x001401D4,
    QueryNetworkInterfaceInfo = 0x001401FC,
    SetReparsePoint = 0x000900A4,
    DfsGetReferralsEx = 0x000601B0,
    FileLevelTrim = 0x00098208,
    ValidateNegotiateInfo = 0x00140204,
}

/// The Length of source/dest keys in SrvCopyChunk* FSCTLs contents.
/// MS-SMB 2.2.31.1

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvCopychunkCopy {
    pub source_key: [u8; Self::SRV_KEY_LENGTH],
    #[bw(try_calc = chunks.len().try_into())]
    chunk_count: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    #[br(count = chunk_count)]
    pub chunks: Vec<SrvCopychunk>,
}

impl SrvCopychunkCopy {
    pub const SRV_KEY_LENGTH: usize = 24;
    pub const SIZE: usize = Self::SRV_KEY_LENGTH + 4 + 4;
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvCopychunk {
    pub source_offset: u64,
    pub target_offset: u64,
    pub length: u32,
    #[bw(calc = 0)]
    _reserved: u32,
}

impl SrvCopychunk {
    pub const SIZE: usize = size_of::<u64>() * 2 + size_of::<u32>() * 2;
}

impl IoctlRequestContent for SrvCopychunkCopy {
    fn get_bin_size(&self) -> u32 {
        (Self::SIZE + self.chunks.len() * SrvCopychunk::SIZE) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvReadHashReq {
    /// Hash type MUST be 1 (SRV_HASH_TYPE_PEER_DIST)
    #[bw(calc = 1)]
    #[br(assert(hash_type == 1))]
    pub hash_type: u32,
    /// Hash version MUST be 1 or 2
    #[br(assert(1 <= hash_version && hash_version <= 2))]
    #[bw(assert(1 <= *hash_version && *hash_version <= 2))]
    pub hash_version: u32,
    pub hash_retrieval_type: SrvHashRetrievalType,
}

impl IoctlRequestContent for SrvReadHashReq {
    fn get_bin_size(&self) -> u32 {
        size_of::<u32>() as u32 * 3
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum SrvHashRetrievalType {
    HashBased = 1,
    FileBased = 2,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkResiliencyRequest {
    pub timeout: u32,
    #[bw(calc = 0)]
    pub _reserved: u32,
}

impl IoctlRequestContent for NetworkResiliencyRequest {
    fn get_bin_size(&self) -> u32 {
        size_of::<u32>() as u32 * 2
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidateNegotiateInfoRequest {
    pub capabilities: u32,
    pub guid: Guid,
    pub security_mode: NegotiateSecurityMode,
    #[bw(try_calc = dialects.len().try_into())]
    dialect_count: u16,
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
}

impl IoctlRequestContent for ValidateNegotiateInfoRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>()
            + Guid::GUID_SIZE
            + 2
            + size_of::<u16>()
            + self.dialects.len() * size_of::<u16>()) as u32
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvCopychunkResponse {
    pub chunks_written: u32,
    pub chunk_bytes_written: u32,
    pub total_bytes_written: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvSnapshotArray {
    pub number_of_snap_shots: u32,
    pub number_of_snap_shots_returned: u32,
    #[bw(calc = PosMarker::default())]
    pub snap_shot_array_size: PosMarker<u32>,
    #[br(parse_with = binrw::helpers::until_eof, map_stream = |s| s.take_seek(snap_shot_array_size.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&snap_shot_array_size))]
    pub snap_shots: Vec<NullWideString>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvRequestResumeKey {
    pub resume_key: [u8; SrvCopychunkCopy::SRV_KEY_LENGTH],
    #[bw(calc = 0)]
    context_length: u32,
    /// This should always be set to empty, according to MS-SMB2 2.2.32.3
    #[br(count = context_length)]
    #[bw(assert(context.len() == context_length as usize))]
    pub context: Vec<u8>,
}

/// A trait that helps parsing FSCTL responses by matching the FSCTL code.
pub trait IoctlFsctlResponseContent: for<'a> BinRead<Args<'a> = ()> + std::fmt::Debug {
    const FSCTL_CODE: FsctlCodes;
}

macro_rules! impl_fsctl_response {
    ($code:ident, $type:ty) => {
        impl IoctlFsctlResponseContent for $type {
            const FSCTL_CODE: FsctlCodes = FsctlCodes::$code;
        }
    };
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvReadHashRes {
    /// Hash type MUST be 1 (SRV_HASH_TYPE_PEER_DIST)
    #[bw(calc = 1)]
    #[br(assert(hash_type == 1))]
    hash_type: u32,
    /// Hash version MUST be 1 or 2
    #[br(assert(1 <= hash_version && hash_version <= 2))]
    #[bw(assert(1 <= *hash_version && *hash_version <= 2))]
    hash_version: u32,
    source_file_change_time: FileTime,
    source_file_size: u64,
    hash_blob_length: PosMarker<u32>,
    hash_blob_offset: PosMarker<u32>,
    dirty: u16,
    #[bw(try_calc = source_file_name.len().try_into())]
    source_file_name_length: u16,
    #[br(count = source_file_name_length)]
    source_file_name: Vec<u8>,
}

impl_fsctl_response!(SrvReadHash, SrvReadHashRes);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvHashRetrieveHashBased {
    pub offset: u64,
    #[bw(try_calc = blob.len().try_into())]
    buffer_length: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    /// TODO: Parse as Content Information File
    #[br(count = buffer_length)]
    blob: Vec<u8>,
}

impl_fsctl_response!(SrvReadHash, SrvHashRetrieveHashBased);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SrvHashRetrieveFileBased {
    pub file_data_offset: u64,
    pub file_data_length: u64,
    #[bw(try_calc = buffer.len().try_into())]
    buffer_length: u32,
    #[bw(calc = 0)]
    _reserved: u32,
    /// TODO: Parse as Content Information File
    #[br(count = buffer_length)]
    pub buffer: Vec<u8>,
}

pub type NetworkInterfaceInfo = ChainedItem<NetworkInterfaceInfoContent>;

impl_fsctl_response!(QueryNetworkInterfaceInfo, NetworkInterfaceInfo);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkInterfaceInfoContent {
    pub if_index: u32,
    pub capability: NetworkInterfaceCapability,
    #[bw(calc = 0)]
    _reserved: u32,
    pub link_speed: u64,
    // -- Inlined sockadd_storage for convenience and performance
    pub sockaddr: SocketAddrStorage,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NetworkInterfaceCapability {
    pub rss: bool,
    pub rdma: bool,
    #[skip]
    __: B30,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum SocketAddrStorage {
    V4(SocketAddrStorageV4),
    V6(SocketAddrStorageV6),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\x02\x00"))] // InterNetwork
pub struct SocketAddrStorageV4 {
    pub port: u16,
    pub address: u32,
    _reserved: [u8; 128 - (2 + 2 + 4)],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\x17\x00"))] // InterNetworkV6
pub struct SocketAddrStorageV6 {
    pub port: u16,
    #[bw(calc = 0)]
    _flow_info: u32,
    pub address: u128,
    #[bw(calc = 0)]
    _scope_id: u32,
    _reserved: [u8; 128 - (2 + 4 + 16 + 4)],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidateNegotiateInfoResponse {
    pub capabilities: u32,
    pub guid: Guid,
    pub security_mode: NegotiateSecurityMode,
    pub dialect: Dialect,
}

impl_fsctl_response!(ValidateNegotiateInfo, ValidateNegotiateInfoResponse);
