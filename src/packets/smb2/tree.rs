use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::pos_marker::PosMarker;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SMB2TreeConnectRquestFlags {
    cluster_reconnect: bool,
    redirect_to_owner: bool,
    extension_present: bool,
    reserved: B13,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2TreeConnectRequest {
    #[bw(calc = 9)]
    #[br(assert(structure_size == 9))]
    structure_size: u16,
    pub flags: SMB2TreeConnectRquestFlags,
    #[bw(calc = PosMarker::default())]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc((buffer.len() as u16).checked_mul(2).ok_or(format!("buffer length overflow {}", buffer.len()))))]
    path_length: u16,
    // TODO: Support extension
    #[brw(little)]
    #[br(count = path_length)]
    #[bw(write_with=PosMarker::write_and_fill_start_offset, args(&_path_offset))]
    pub buffer: Vec<u16>
}

impl SMB2TreeConnectRequest {
    pub fn new(name: String) -> SMB2TreeConnectRequest {
        SMB2TreeConnectRequest {
            flags: SMB2TreeConnectRquestFlags::new(),
            buffer: name.encode_utf16().collect(),
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2TreeConnectResponse {
    #[bw(calc = 16)]
    #[br(assert(structure_size == 16))]
    structure_size: u16,
    pub share_type: SMB2TreeConnectShareType,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u8,
    pub share_flags: SMB2TreeShareFlags,
    pub capabilities: SMB2TreeCapabilities,
    pub maximal_access: u32,
}

#[derive(BitfieldSpecifier, Debug, Clone, Copy)]
#[bits = 4]
pub enum SMB2TreeConnectShareFlagsCacheMode {
    Manual,
    Auto,
    Vdo,
    NoCache
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SMB2TreeShareFlags {
    dfs: bool,
    dfs_root: bool,
    #[allow(non_snake_case)]
    _reserved1: B2,
    caching_mode: SMB2TreeConnectShareFlagsCacheMode,

    restrict_exclusive_opens: bool,
    smb2_shareflag_force_shared_delete: bool,
    allow_namespace_caching: bool,
    access_based_directory_enum: bool,
    force_levelii_oplock: bool,
    enable_hash_v1: bool,
    enable_hash_v2: bool,
    encrypt_data : bool,

    #[allow(non_snake_case)]
    _reserved2: B2,
    identity_remoting: bool,
    #[allow(non_snake_case)]
    _reserved3: B1,
    compress_data: bool,
    isolated_transport: bool,
    #[allow(non_snake_case)]
    _reserved4: B10,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
struct SMB2TreeCapabilities {
    #[allow(non_snake_case)]
    _reserved1: B3,
    dfs: bool,
    continuous_availability: bool,
    scaleout: bool,
    cluster: bool,
    asymmetric: bool,

    redirect_to_owner: bool,
    #[allow(non_snake_case)]
    _reserved: B23
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u8))]
pub enum SMB2TreeConnectShareType {
    Disk,
    Pipe,
    Print,
}