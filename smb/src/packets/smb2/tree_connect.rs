use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::super::binrw_util::prelude::*;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct TreeConnectRequestFlags {
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
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    pub flags: TreeConnectRequestFlags,
    #[bw(calc = PosMarker::default())]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.size().try_into())]
    path_length: u16,
    // TODO: Support extension
    #[brw(little)]
    #[br(args(path_length as u64))]
    #[bw(write_with=PosMarker::write_aoff, args(&_path_offset))]
    pub buffer: SizedWideString,
}

impl TreeConnectRequest {
    pub fn new(name: &String) -> TreeConnectRequest {
        TreeConnectRequest {
            flags: TreeConnectRequestFlags::new(),
            buffer: name.clone().into(),
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TreeConnectResponse {
    #[bw(calc = 16)]
    #[br(assert(_structure_size == 16))]
    _structure_size: u16,
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
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum TreeConnectShareType {
    Disk = 0x1,
    Pipe = 0x2,
    Print = 0x3,
}

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct TreeDisconnectRequest {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeDisconnectResponse {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_tree_connect_req_write() {
        let result = encode_content(Content::TreeConnectRequest(TreeConnectRequest::new(
            &r"\\127.0.0.1\MyShare".into(),
        )));
        assert_eq!(
            result,
            [
                0x9, 0x0, 0x0, 0x0, 0x48, 0x0, 0x26, 0x0, 0x5c, 0x0, 0x5c, 0x0, 0x31, 0x0, 0x32,
                0x0, 0x37, 0x0, 0x2e, 0x0, 0x30, 0x0, 0x2e, 0x0, 0x30, 0x0, 0x2e, 0x0, 0x31, 0x0,
                0x5c, 0x0, 0x4d, 0x0, 0x79, 0x0, 0x53, 0x0, 0x68, 0x0, 0x61, 0x0, 0x72, 0x0, 0x65,
                0x0
            ]
        );
    }

    #[test]
    pub fn test_tree_connect_res_parse() {
        let mut cursor = Cursor::new(&[
            0x10, 0x0, 0x1, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x1, 0x1f, 0x0,
        ]);
        let content_parsed = TreeConnectResponse::read_le(&mut cursor).unwrap();
        assert_eq!(
            content_parsed,
            TreeConnectResponse {
                share_type: TreeConnectShareType::Disk,
                share_flags: TreeShareFlags::new().with_access_based_directory_enum(true),
                capabilities: TreeCapabilities::new(),
                maximal_access: 0x001f01ff,
            }
        )
    }
}
