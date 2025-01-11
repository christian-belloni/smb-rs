//! File System Control Codes (MS-FSCC)
//!
//! Implemented using modular_bitfield and binrw, for use in SMB2 messages.

use std::io::Cursor;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::super::binrw_util::prelude::*;

/// MS-FSCC 2.6
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    #[skip]
    __: bool,

    pub directory: bool,
    pub archive: bool,
    #[skip]
    __: bool,
    pub normal: bool,

    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,

    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
    pub integrity_stream: bool,

    #[skip]
    __: bool,
    pub no_scrub_data: bool,
    pub recall_on_open: bool,
    pub pinned: bool,

    pub unpinned: bool,
    #[skip]
    __: bool,
    pub recall_on_data_access: bool,
    #[skip]
    __: B9,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct FileAccessMask {
    pub file_read_data: bool,
    pub file_write_data: bool,
    pub file_append_data: bool,
    pub file_read_ea: bool,

    pub file_write_ea: bool,
    pub file_execute: bool,
    pub file_delete_child: bool,
    pub file_read_attributes: bool,

    pub file_write_attributes: bool,
    #[skip]
    __: B7,

    pub delete: bool,
    pub read_control: bool,
    pub write_dac: bool,
    pub write_owner: bool,

    pub synchronize: bool,
    #[skip]
    __: B3,

    pub access_system_security: bool,
    pub maximum_allowed: bool,
    #[skip]
    __: B2,

    pub generic_all: bool,
    pub generic_execute: bool,
    pub generic_write: bool,
    pub generic_read: bool,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct DirAccessMask {
    pub file_list_directory: bool,
    pub file_add_file: bool,
    pub file_add_subdirectory: bool,
    pub file_read_ea: bool,

    pub file_write_ea: bool,
    pub file_traverse: bool,
    pub file_delete_child: bool,
    pub file_read_attributes: bool,

    pub file_write_attributes: bool,
    #[skip]
    __: B7,

    pub delete: bool,
    pub read_control: bool,
    pub write_dac: bool,
    pub write_owner: bool,

    pub synchronize: bool,
    #[skip]
    __: B3,

    pub access_system_security: bool,
    pub maximum_allowed: bool,
    #[skip]
    __: B2,

    pub generic_all: bool,
    pub generic_execute: bool,
    pub generic_write: bool,
    pub generic_read: bool,
}

impl From<FileAccessMask> for DirAccessMask {
    fn from(mask: FileAccessMask) -> Self {
        // The bits are the same, just the names are different.
        Self::from_bytes(mask.into_bytes())
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr = u8)]
pub enum FileInformationClass {
    DirectoryInformation = 0x01,
    FullDirectoryInformation = 0x02,
    IdFullDirectoryInformation = 0x26,
    BothDirectoryInformation = 0x03,
    IdBothDirectoryInformation = 0x25,
    NamesInformation = 0x0C,
    IdExtdDirectoryInformation = 0x3c,
    Id64ExtdDirectoryInformation = 0x4e,
    Id64ExtdBothDirectoryInformation = 0x4f,
    IdAllExtdDirectoryInformation = 0x50,
    IdAllExtdBothDirectoryInformation = 0x51,
    // reserved.
    InformationClassReserved = 0x64,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(import(c: FileInformationClass))]
#[brw(little)]
pub enum DirectoryInfoVector {
    #[br(pre_assert(c == FileInformationClass::IdBothDirectoryInformation))]
    IdBothDirectoryInformation(IdBothDirectoryInfoVector),
}

impl DirectoryInfoVector {
    pub fn parse(payload: &[u8], class: FileInformationClass) -> Result<Self, binrw::Error> {
        let mut cursor = Cursor::new(payload);
        Self::read_args(&mut cursor, (class,))
    }
}

impl DirectoryInfoVector {
    pub const SUPPORTED_CLASSES: [FileInformationClass; 1] =
        [FileInformationClass::DirectoryInformation];
}

#[binrw::binrw]
#[derive(Debug)]
pub struct IdBothDirectoryInfoVector {
    #[br(parse_with = binrw::helpers::until_eof)]
    val: Vec<BothDirectoryInformationItem>,
}

impl Into<Vec<BothDirectoryInformationItem>> for IdBothDirectoryInfoVector {
    fn into(self) -> Vec<BothDirectoryInformationItem> {
        self.val
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct BothDirectoryInformationItem {
    #[bw(calc = PosMarker::default())]
    _next_entry_offset: PosMarker<u32>,
    pub file_index: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: FileAttributes,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32, // bytes
    pub ea_size: u32,
    pub short_name_length: u8,
    #[bw(calc = 0)]
    #[br(assert(_reserved1 == 0))]
    _reserved1: u8,
    pub short_name: [u16; 12], // 8.3
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u16,
    pub fild_id: u64,
    #[br(args(_file_name_length as u64))]
    pub file_name: SizedWideString,
    // Seek to next item if exists.
    #[br(seek_before = _next_entry_offset.seek_relative(true))]
    #[bw(calc = ())]
    _seek_next_if_exists: (),
}
