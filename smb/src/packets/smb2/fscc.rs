//! File System Control Codes (MS-FSCC)
//!
//! The FSCC types are widely used in SMB messages.
use paste::paste;

use std::io::Cursor;

use binrw::{io::TakeSeekExt, prelude::*, NullString};
use modular_bitfield::prelude::*;

use crate::access_mask;

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

access_mask! {
pub struct FileAccessMask {
    file_read_data: bool,
    file_write_data: bool,
    file_append_data: bool,
    file_read_ea: bool,

    file_write_ea: bool,
    file_execute: bool,
    file_delete_child: bool,
    file_read_attributes: bool,

    file_write_attributes: bool,
    #[skip]
    __: B7,
}}

access_mask! {
pub struct DirAccessMask {
    list_directory: bool,
    add_file: bool,
    add_subdirectory: bool,
    read_ea: bool,

    write_ea: bool,
    traverse: bool,
    delete_child: bool,
    read_attributes: bool,

    write_attributes: bool,
    #[skip]
    __: B7,
}}

impl From<FileAccessMask> for DirAccessMask {
    fn from(mask: FileAccessMask) -> Self {
        // The bits are the same, just the names are different.
        Self::from_bytes(mask.into_bytes())
    }
}

// TODO: Make it generic, so it will be easy-peasy to use!
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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(has_next: bool))]
pub struct FileNotifyInformation {
    #[br(assert(next_entry_offset.value % 4 == 0))]
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    pub action: NotifyAction,
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args(file_name_length.into()))]
    pub file_name: SizedWideString,

    // Handle next entry.
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(has_next))]
    #[bw(align_before = 4)]
    #[bw(write_with = PosMarker::write_aoff, args(&next_entry_offset))]
    _seek_next: (),
}

impl FileNotifyInformation {
    pub fn new(action: NotifyAction, file_name: &str) -> Self {
        Self {
            action,
            file_name: SizedWideString::from(file_name),
            _seek_next: (),
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NotifyAction {
    Added = 0x1,
    Removed = 0x2,
    Modified = 0x3,
    RenamedOldName = 0x4,
    RenamedNewName = 0x5,
    AddedStream = 0x6,
    RemovedStream = 0x7,
    ModifiedStream = 0x8,
    RemovedByDelete = 0x9,
    IdNotTunnelled = 0xa,
    TunnelledIdCollision = 0xb,
}

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(has_next: bool))]
pub struct FileGetEaInformation {
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    // ea_name_length is the STRING LENGTH of ea_name -- excluding the null terminator!
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[br(map_stream = |s| s.take_seek(ea_name_length as u64))]
    pub ea_name: NullString,

    // Seek to next item if exists.
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(has_next))]
    #[bw(write_with = PosMarker::write_aoff, args(&next_entry_offset))]
    pub _seek_next_if_exists: (),
}

impl FileGetEaInformation {
    pub fn new(ea_name: &str) -> Self {
        Self {
            ea_name: NullString::from(ea_name),
            _seek_next_if_exists: (),
        }
    }

    /// A [binrw::writer] function to write a list of [FileGetEaInformation] items.
    /// It makes sure that next_entry_offset is properly set, and should always be used
    /// to write a list of [FileGetEaInformation] items.
    #[binrw::writer(writer, endian)]
    pub fn write_list(value: &Vec<Self>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            let has_next = i < value.len() - 1;
            item.write_options(writer, endian, (has_next,))?;
        }
        Ok(())
    }
}

/// A macro for generating a file class enums,
/// for both the file information class, and information value.
macro_rules! file_info_classes {
    ($svis:vis $name:ident {
        $($vis:vis $field_name:ident = $cid:literal,)+
    }) => {
        paste! {
            // Enum for Class IDs
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq, Clone, Copy)]
            #[brw(repr(u8))]
            $svis enum [<$name Class>] {
                $(
                    $vis [<$field_name Information>] = $cid,
                )*
            }

            // Enum for class values
            #[binrw::binrw]
            #[derive(Debug, PartialEq, Eq)]
            #[brw(little)]
            #[br(import(c: [<$name Class>]))]
            $svis enum $name {
                $(
                    #[br(pre_assert(matches!(c, [<$name Class>]::[<$field_name Information>])))]
                    [<$field_name Information>]([<File $field_name Information>]),
                )*
            }

            impl $name {
                $svis fn class(&self) -> [<$name Class>] {
                    match self {
                        $(
                            $name::[<$field_name Information>](_) => [<$name Class>]::[<$field_name Information>],
                        )*
                    }
                }
            }
        }
    }
}

file_info_classes! {
    pub QueryFileInfo {
        pub Basic = 4,
        pub FullEa = 15,
        pub NetworkOpen = 34,
    }
}

file_info_classes! {
    pub SetFileInfo {
        pub EndOfFile = 20,
        pub Disposition = 13,
        pub Rename = 10,
    }
}

file_info_classes! {
    pub QueryDirectoryInfo {
        pub IdBothDirectoryInformation = 37,
    }
}

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
pub struct FileFullEaInformation {
    // TODO
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
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

    #[br(seek_before = next_entry_offset.seek_relative(true))]
    __: (),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileEndOfFileInformation {
    pub end_of_file: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileDispositionInformation {
    pub delete_pending: u8,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileRenameInformation2 {
    pub replace_if_exists: u8,
    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    _reserved2: u16,
    #[bw(calc = 0)]
    _reserved3: u32,
    pub root_directory: u64,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    #[br(args(_file_name_length as u64))]
    pub file_name: SizedWideString,
}
type FileRenameInformation = FileRenameInformation2;

#[binrw::binrw]
#[derive(Debug)]
pub struct FileQuotaInformation {
    _next_entry_offset: u32,
    sid_length: u32,
    change_time: FileTime,
    quota_used: u64,
    quota_threshold: u64,
    quota_limit: u64,
    // TODO: Parse properly.
    #[br(count = sid_length)]
    sid: Vec<u8>,
}
