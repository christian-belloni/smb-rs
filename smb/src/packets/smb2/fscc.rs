//! File System Control Codes (MS-FSCC)
//!
//! The FSCC types are widely used in SMB messages.
use std::ops::Deref;

use binrw::{io::TakeSeekExt, prelude::*, NullString};
use modular_bitfield::prelude::*;
use paste::paste;

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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileIdBothDirectoryInformationInner {
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
}

pub type FileIdBothDirectoryInformation = ChainedItem<FileIdBothDirectoryInformationInner>;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(has_next: bool))]
pub struct FileNotifyInformationInner {
    pub action: NotifyAction,
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    #[br(args(file_name_length.into()))]
    pub file_name: SizedWideString,
}

pub type FileNotifyInformation = ChainedItem<FileNotifyInformationInner>;

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
pub struct FileGetEaInformationInner {
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[br(map_stream = |s| s.take_seek(ea_name_length as u64))]
    pub ea_name: NullString,
}

pub type FileGetEaInformation = ChainedItem<FileGetEaInformationInner>;

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

            $(
                impl Into<$name> for [<File $field_name Information>] {
                    fn into(self) -> $name {
                        $name::[<$field_name Information>](self)
                    }
                }
            )*
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
        pub IdBothDirectory = 37,
    }
}

impl QueryDirectoryInfo {
    pub fn read_output(
        output: &Vec<u8>,
        class: QueryDirectoryInfoClass,
    ) -> BinResult<Vec<QueryDirectoryInfo>> {
        let mut reader = std::io::Cursor::new(output);
        let mut result = vec![];
        while reader.position() < output.len() as u64 {
            let item = match class {
                QueryDirectoryInfoClass::IdBothDirectoryInformation => {
                    Self::read_item::<FileIdBothDirectoryInformation>(&mut reader)?
                }
            };
            result.push(item);
        }
        Ok(result)
    }

    fn read_item<T>(reader: &mut std::io::Cursor<&Vec<u8>>) -> BinResult<QueryDirectoryInfo>
    where
        T: BinRead + Into<QueryDirectoryInfo>,
        for<'a> T::Args<'a>: Default,
    {
        let item = T::read_le(reader)?;
        Ok(item.into())
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
pub struct FileNetworkOpenInformationInner {
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

pub type FileNetworkOpenInformation = ChainedItem<FileNetworkOpenInformationInner>;

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
pub struct FileQuotaInformationInner {
    sid_length: u32,
    change_time: FileTime,
    quota_used: u64,
    quota_threshold: u64,
    quota_limit: u64,
    // TODO: Parse properly.
    #[br(count = sid_length)]
    sid: Vec<u8>,
}

pub type FileQuotaInformation = ChainedItem<FileQuotaInformationInner>;

/// A genric utility struct to wrap "chained"-encoded entries.
/// Many fscc-query structs have a common "next entry offset" field,
/// which is used to chain multiple entries together.
/// This struct wraps the value, and the offset, and provides a way to iterate over them.
/// See [ChainedItem<T>::write_chained] to see how to write this type when in a list.
#[binrw::binrw]
#[derive(Debug)]
#[bw(import(last: bool))]
pub struct ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(assert(next_entry_offset.value % 4 == 0))]
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    value: T,
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(!last))]
    #[bw(align_before = 4)]
    #[bw(write_with = PosMarker::write_roff, args(&next_entry_offset))]
    __: (),
}

impl<T> ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[binrw::writer(writer, endian)]
    pub fn write_chained(value: &Vec<ChainedItem<T>>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            item.write_options(writer, endian, (i == value.len() - 1,))?;
        }
        Ok(())
    }
}

impl<T> PartialEq for ChainedItem<T>
where
    T: BinRead + BinWrite + PartialEq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> Eq for ChainedItem<T>
where
    T: BinRead + BinWrite + Eq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
}

impl<T> Deref for ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> From<T> for ChainedItem<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(value: T) -> Self {
        Self { value, __: () }
    }
}
