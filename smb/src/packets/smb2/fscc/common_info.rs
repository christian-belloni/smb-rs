use binrw::{prelude::*, NullString};
use modular_bitfield::prelude::*;

use crate::packets::binrw_util::prelude::{FileTime, SizedWideString};

use super::{ChainedItem, FileAttributes};

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileBasicInformation {
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFullEaInformationInner {
    pub flags: u8,
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[bw(calc = match ea_value {
        Some(v) => v.len() as u16,
        None => 0
    })]
    ea_value_length: u16,
    #[br(assert(ea_name.len() == ea_name_length as usize))]
    pub ea_name: NullString,
    #[br(if(ea_value_length > 0))]
    #[br(count = ea_value_length)]
    pub ea_value: Option<Vec<u8>>,
}

pub type FileFullEaInformationCommon = ChainedItem<FileFullEaInformationInner>;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct FileModeInformation {
    #[skip]
    __: bool,
    pub write_through: bool,
    pub sequential_access: bool,
    pub no_intermediate_buffering: bool,

    pub syncronous_io_alert: bool,
    pub syncronous_io_non_alert: bool,
    #[skip]
    __: B6,

    pub delete_on_close: bool,
    #[skip]
    __: B19,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeInformation {
    pub read_mode: PipeReadMode,
    pub completion_mode: PipeCompletionMode,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum PipeReadMode {
    Stream = 0,
    Message = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum PipeCompletionMode {
    Queue = 0,
    Complete = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePositionInformation {
    pub current_byte_offset: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNameInformation {
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args(file_name_length as u64))]
    pub file_name: SizedWideString,
}
