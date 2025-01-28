use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::super::guid::Guid;
use super::fscc::*;
use crate::packets::binrw_util::prelude::*;

#[binrw::binrw]
pub struct ChangeNotifyRequest {
    #[bw(calc = 32)]
    #[br(assert(structure_size == 32))]
    structure_size: u16,
    flags: NotifyFlags,
    output_buffer_length: u32,
    file_id: Guid,
    completion_filter: NotifyFilter,
    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u32,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NotifyFlags {
    pub watch_tree: bool,
    #[skip]
    __: B15,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct NotifyFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,

    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,

    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
    pub stream_write: bool,

    #[skip]
    __: B20,
}

#[binrw::binrw]
pub struct ChangeNotifyResponse {
    #[bw(calc = 9)]
    #[br(assert(structure_size == 9))]
    structure_size: u16,
    output_buffer_offset: PosMarker<u16>,
    output_buffer_length: PosMarker<u32>,
    // TODO: #[bw(...)]
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length.value.into()))]
    buffer: FileNotifyInformation,
}

#[cfg(test)]
mod tests {
    // TODO: Add tests!
}
