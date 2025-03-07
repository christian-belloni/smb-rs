use std::ops::Deref;

use binrw::{io::TakeSeekExt, prelude::*, NullString};

use crate::{
    file_info_classes,
    packets::binrw_util::{
        helpers::Boolean,
        prelude::{FileTime, SizedWideString},
    },
};

use super::{
    ChainedItem, FileAccessMask, FileAttributes, FileBasicInformation, FileFullEaInformationCommon,
    FileModeInformation, FileNameInformation, FilePipeInformation, FilePositionInformation,
};

file_info_classes! {
    pub QueryFileInfo {
        pub Access = 8,
        pub Alignment = 17,
        pub All = 18,
        pub AlternateName = 21,
        pub AttributeTag = 35,
        pub Basic = 4,
        pub Compression = 28,
        pub Ea = 7,
        pub FullEa = 15,
        pub Id = 59,
        pub Internal = 6,
        pub Mode = 16,
        pub NetworkOpen = 34,
        pub NormalizedName = 48,
        pub Pipe = 23,
        pub PipeLocal = 24,
        pub PipeRemote  = 25,
        pub Position = 14,
        pub Standard = 5,
        pub Stream = 22,
    }, Read
}

pub type FileFullEaInformation = FileFullEaInformationCommon;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAccessInformation {
    access_flags: FileAccessMask,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAllInformation {
    basic: FileBasicInformation,
    standard: FileStandardInformation,
    internal: FileInternalInformation,
    ea: FileEaInformation,
    access: FileAccessInformation,
    position: FilePositionInformation,
    mode: FileModeInformation,
    alignment: FileAlignmentInformation,
    name: FileNameInformation,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum FileAlignmentInformation {
    Byte = 0,
    Word = 1,
    Long = 3,
    Quad = 7,
    Octa = 0xf,
    _32Byte = 0x1f,
    _64Byte = 0x3f,
    _128Byte = 0x7f,
    _256Byte = 0xff,
    _512Byte = 0x1ff,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAlternateNameInformation {
    inner: FileNameInformation,
}

impl Deref for FileAlternateNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAttributeTagInformation {
    file_attributes: u32,
    reparse_tag: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileCompressionInformation {
    compressed_file_size: u64,
    compression_format: FileCompressionFormat,
    compression_unit: u8,
    chunk_shift: u8,
    cluster_shift: u8,
    #[br(parse_with = binrw::helpers::read_u24)]
    #[br(assert(reserved == 0))]
    #[bw(align_before = 4)]
    #[bw(ignore)]
    reserved: u32, // 3-bytes. TODO: Define a normal u24 type for such cases?
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum FileCompressionFormat {
    None = 0,
    Lznt1 = 2,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileEaInformation {
    ea_size: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileIdInformation {
    volume_serial_number: u64,
    file_id: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileInternalInformation {
    index_number: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNetworkOpenInformation {
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    change_time: FileTime,
    allocation_size: u64,
    end_of_file: u64,
    file_attributes: FileAttributes,
    #[bw(calc = 0)]
    _reserved: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNormalizedNameInformation {
    inner: FileNameInformation,
}

impl Deref for FileNormalizedNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeLocalInformation {
    named_pipe_type: NamedPipeType,
    named_pipe_configuration: NamedPipeConfiguration,
    maximum_instances: u32,
    current_instances: u32,
    inbound_quota: u32,
    outbound_quota: u32,
    write_quota: u32,
    named_pipe_state: NamedPipeState,
    named_pipe_end: NamedPipeEnd,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeType {
    ByteStream = 0,
    Message = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeConfiguration {
    Inbound = 0,
    Outbound = 1,
    FullDuplex = 2,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeState {
    Disconnected = 1,
    Listening = 2,
    Connected = 3,
    Closing = 4,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NamedPipeEnd {
    Client = 0,
    Server = 1,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeRemoteInformation {
    collect_data_time: FileTime,
    maximum_collection_count: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileStandardInformation {
    allocation_size: u64,
    end_of_file: u64,
    number_of_links: u32,
    delete_pending: Boolean,
    directory: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileStreamInformation {
    #[bw(try_calc = stream_name.size().try_into())]
    stream_name_length: u32,
    stream_size: u64,
    stream_allocation_size: u64,
    #[br(args(stream_name_length as u64))]
    stream_name: SizedWideString,
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
