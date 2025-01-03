use binrw::io::TakeSeekExt;
use std::io::SeekFrom;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::pos_marker::PosMarker;

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2QueryDirectoryRequest {
    #[bw(calc = 33)]
    #[br(assert(_structure_size == 33))]
    _structure_size: u16,
    pub file_information_class: FileInformationClass,
    pub flags: QueryDirectoryFlags,
    // If SMB2_INDEX_SPECIFIED is set in Flags, this value MUST be supplied.
    // Otherwise, it MUST be set to zero and the server MUST ignore it.
    #[bw(assert(flags.index_specified() || *file_index == 0))]
    pub file_index: u32,
    pub file_id: u128,
    #[bw(calc = PosMarker::default())]
    pub file_name_offset: PosMarker<u16>,
    #[bw(try_calc = TryInto::<u16>::try_into(file_name.len()).unwrap().checked_mul(2).ok_or("file_name too long"))]
    file_name_length: u16, // in bytes.
    pub output_buffer_length: u32,
    #[br(seek_before = SeekFrom::Start(file_name_offset.value as u64))]
    // map stream take until eof:
    #[br(map_stream = |s| s.take_seek(file_name_length as u64), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&file_name_offset))]
    pub file_name: Vec<u16>,
}

#[derive(BinRead, BinWrite, Debug)]
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

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct QueryDirectoryFlags {
    pub restart_scans: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    pub reopen: bool,
    #[allow(non_snake_case)]
    _reserved: B4,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2QueryDirectoryResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    #[bw(calc = PosMarker::default())]
    output_buffer_offset: PosMarker<u16>,
    #[bw(try_calc = output_buffer.len().try_into())]
    output_buffer_length: u32,
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length as u64), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&output_buffer_offset))]
    pub output_buffer: Vec<u8>,
}
