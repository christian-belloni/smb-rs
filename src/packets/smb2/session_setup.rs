use binrw::prelude::*;

use super::super::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SessionSetupRequest {
    #[bw(calc = 25)]
    #[br(assert(structure_size == 25))]
    structure_size: u16,
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32,
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

impl SessionSetupRequest {
    pub fn new(buffer: Vec<u8>) -> SessionSetupRequest {
        SessionSetupRequest {
            flags: 0,
            security_mode: 1,
            capabilities: 1,
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
    pub session_flags: u16,
    pub security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&security_buffer_offset))]
    pub buffer: Vec<u8>,
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
