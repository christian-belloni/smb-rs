use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::super::binrw_util::prelude::*;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeConnectRquestFlags {
    pub cluster_reconnect: bool,
    pub redirect_to_owner: bool,
    pub extension_present: bool,
    #[skip]
    __: B13,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeConnectRequest {
    #[bw(calc = 9)]
    #[br(assert(structure_size == 9))]
    structure_size: u16,
    pub flags: TreeConnectRquestFlags,
    #[bw(calc = PosMarker::default())]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.size().try_into())]
    path_length: u16,
    // TODO: Support extension
    #[brw(little)]
    #[br(args(path_length as u64))]
    #[bw(write_with=PosMarker::write_and_fill_offset, args(&_path_offset))]
    pub buffer: SizedWideString,
}

impl TreeConnectRequest {
    pub fn new(name: &String) -> TreeConnectRequest {
        TreeConnectRequest {
            flags: TreeConnectRquestFlags::new(),
            buffer: name.clone().into(),
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeConnectResponse {
    #[bw(calc = 16)]
    #[br(assert(structure_size == 16))]
    structure_size: u16,
    pub share_type: TreeConnectShareType,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u8,
    pub share_flags: TreeShareFlags,
    pub capabilities: TreeCapabilities,
    pub maximal_access: u32,
}

#[derive(BitfieldSpecifier, Debug, Clone, Copy)]
#[bits = 4]
pub enum TreeConnectShareFlagsCacheMode {
    Manual,
    Auto,
    Vdo,
    NoCache,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeShareFlags {
    pub dfs: bool,
    pub dfs_root: bool,
    #[skip]
    __: B2,
    pub caching_mode: TreeConnectShareFlagsCacheMode,

    pub restrict_exclusive_opens: bool,
    pub smb2_shareflag_force_shared_delete: bool,
    pub allow_namespace_caching: bool,
    pub access_based_directory_enum: bool,
    pub force_levelii_oplock: bool,
    pub enable_hash_v1: bool,
    pub enable_hash_v2: bool,
    pub encrypt_data: bool,

    #[skip]
    __: B2,
    pub identity_remoting: bool,
    #[skip]
    __: B1,
    pub compress_data: bool,
    pub isolated_transport: bool,
    #[skip]
    __: B10,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeCapabilities {
    #[skip]
    __: B3,
    pub dfs: bool,
    pub continuous_availability: bool,
    pub scaleout: bool,
    pub cluster: bool,
    pub asymmetric: bool,

    pub redirect_to_owner: bool,
    #[skip]
    __: B23,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u8))]
pub enum TreeConnectShareType {
    Disk,
    Pipe,
    Print,
}

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct TreeDisconnectRequest {
    #[bw(calc = 4)]
    #[br(assert(structure_size == 4))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeDisconnectResponse {
    #[bw(calc = 4)]
    #[br(assert(structure_size == 4))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}
