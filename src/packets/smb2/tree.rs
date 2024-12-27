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
    #[bw(try_calc(buffer.len().try_into()))]
    path_length: u16,
    // TODO: Support extension
    #[br(count = path_length)]
    #[bw(write_with= PosMarker::write_and_fill_start_offset, args(&_path_offset))]
    pub buffer: Vec<u8>
}

impl SMB2TreeConnectRequest {
    pub fn new(buffer: Vec<u8>) -> SMB2TreeConnectRequest {
        SMB2TreeConnectRequest {
            flags: SMB2TreeConnectRquestFlags::new(),
            buffer,
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
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u8))]
pub enum SMB2TreeConnectShareType {
    Disk,
    Pipe,
    Print,
}