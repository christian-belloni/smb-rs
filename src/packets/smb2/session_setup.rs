use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::super::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SessionSetupRequest {
    #[bw(calc = 25)]
    #[br(assert(structure_size == 25))]
    structure_size: u16,
    pub flags: SetupRequestFlags,
    pub security_mode: SecurityMode,
    pub capabilities: NegotiateCapabilities,
    pub channel: u32,
    #[bw(calc = PosMarker::default())]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    pub previous_session_id: u64,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip] __: B6,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SetupRequestFlags {
    pub binding: bool,
    #[skip] __: B7
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NegotiateCapabilities {
    pub dfs: bool,
    #[skip] __: B31,
}

impl SessionSetupRequest {
    pub fn new(buffer: Vec<u8>) -> SessionSetupRequest {
        SessionSetupRequest {
            flags: SetupRequestFlags::new(),
            security_mode: SecurityMode::new().with_signing_enabled(true),
            capabilities: NegotiateCapabilities::new().with_dfs(true),
            channel: 0,
            previous_session_id: 0,
            buffer,
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SessionSetupResponse {
    #[bw(calc = 9)]
    #[br(assert(structure_size == 9))]
    structure_size: u16,
    pub session_flags: SessionFlags,
    pub security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&security_buffer_offset))]
    pub buffer: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SessionFlags {
    pub is_guest: bool,
    pub is_null_session: bool,
    pub encrypt_data: bool,
    #[skip] __: B13,
}

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct LogoffRequest {
    #[bw(calc = 4)]
    #[br(assert(structure_size == 4))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LogoffResponse {
    #[bw(calc = 4)]
    #[br(assert(structure_size == 4))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}
