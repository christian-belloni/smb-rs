use std::io::SeekFrom;

use crate::pos_marker::PosMarker;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
struct SMB2CreateRequest {
    #[bw(calc = 57)]
    #[br(assert(structure_size == 57))]
    structure_size: u16,
    // reserved!
    #[bw(calc = 0)]
    #[br(assert(_security_flags == 0))]
    _security_flags: u8,
    requested_oplock_level: OplockLevel,
    impersonation_level: u32,
    smb_create_flags: u128,
    reserved: u128,
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(name.len()).unwrap())]
    name_length: u16,
    #[bw(calc = PosMarker::default())]
    _create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _create_contexts_length: PosMarker<u32>,

    #[brw(align_before = 8)]
    #[br(count = name_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&_name_offset))]
    name: Vec<u16>,

    #[brw(align_before = 8)]
    #[br(map_stream = |s| s.take_seek(_create_contexts_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = write_context_list, args(&_create_contexts_offset, &_create_contexts_length))]
    contexts: Vec<SMB2CreateContext>,
}

#[binrw::binrw]
#[derive(Debug)]
struct SMB2CreateResponse {
    #[bw(calc = 89)]
    #[br(assert(structure_size == 89))]
    structure_size: u16,
    oplock_level: OplockLevel,
    // always 1 or 0, depends on dialect.
    #[br(assert(flags == 0 || flags == 1))]
    #[bw(assert(*flags == 0 || *flags == 1))]
    flags: u8,
    create_action: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    allocation_size: u64,
    endof_file: u64,
    file_attributes: u32,
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,
    file_id: u128,
    // assert it's 8-aligned
    #[br(assert(create_contexts_offset.value & 0x7 == 0))]
    #[bw(calc = PosMarker::default())]
    create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    create_contexts_length: PosMarker<u32>,
    #[br(seek_before = SeekFrom::Start(create_contexts_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(create_contexts_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = write_context_list, args(&create_contexts_offset, &create_contexts_length))]
    create_contexts: Vec<SMB2CreateContext>,
}

/// Writes the create context list.
///
/// Handles the following issues:
/// 1. Both offset and BYTE size have to be written to some PosMarker<>s.
/// 2. The next parameter shall only be filled if there is a next context.
///
/// This function assumes all import()s for contexts stay the same.
/// Modify with caution.
#[binrw::writer(writer, endian)]
fn write_context_list(
    contexts: &Vec<SMB2CreateContext>,
    offset_dest: &PosMarker<u32>,
    size_bytes_dest: &PosMarker<u32>,
) -> BinResult<()> {
    // 1.a. write start offset and get back to the end of the file
    let start_offset = offset_dest.do_writeback_offset(writer, endian)?;

    // 2. write the list, pass on `is_last`.
    for (i, context) in contexts.iter().enumerate() {
        let is_last = i == contexts.len() - 1;
        context.write_options(writer, endian, (is_last,))?;
    }

    // 2.b. write size of the list
    let size_bytes = writer.stream_position()? - start_offset;
    size_bytes_dest.do_writeback(size_bytes, writer, endian)?;
    Ok(())
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u8))]
enum OplockLevel {
    NONE = 0,
    II = 1,
    EXCLUSIVE = 8,
    BATCH = 9,
    LEASE = 0xff,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(import(has_next: bool))]
struct SMB2CreateContext {
    #[bw(calc = PosMarker::default())]
    _next: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(name.len()).unwrap())]
    name_length: u16,
    reserved: u16,
    #[bw(calc = PosMarker::default())]
    _data_offset: PosMarker<u16>,
    #[bw(calc = u32::try_from(data.len()).unwrap())]
    data_length: u32,
    #[brw(align_before = 8)]
    #[br(count = name_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&_name_offset))]
    name: Vec<u8>,
    #[brw(align_before = 8)]
    #[br(count = data_length)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&_data_offset))]
    data: Vec<u8>,

    // The following value writes next if has_next is true,
    #[brw(if(has_next))]
    // Fill the next offset
    // and also make sure to align to 8 bytes right afterwords.
    #[bw(align_before = 8)]
    #[bw(write_with = PosMarker::write_and_fill_relative_offset, args(&_next))]
    // When reading, move the stream to the next context if there is one.
    #[br(seek_before = SeekFrom::Start(_next.pos.get() + _next.value as u64))]
    fill_next: (),
}
