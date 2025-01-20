//! Get/Set Info Request/Response

use super::super::binrw_util::prelude::*;
use super::fscc::*;
use binrw::{io::TakeSeekExt, prelude::*};
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryInfoRequest {
    #[bw(calc = 41)]
    #[br(assert(structure_size == 41))]
    structure_size: u16,
    info_type: QueryInfoType,
    // TODO: Support non-file info types below:
    file_info_class: FileInfoClass,
    output_buffer_length: u32,
    #[bw(calc = PosMarker::default())]
    _input_buffer_offset: PosMarker<u16>,
    #[br(assert(reserved == 0))]
    #[bw(calc = 0)]
    reserved: u16,
    #[bw(calc = PosMarker::default())]
    input_buffer_length: PosMarker<u32>,
    additional_information: QueryAdditionalInfo,
    flags: QueryInfoFlags,
    file_id: Guid,
    #[br(map_stream = |s| s.take_seek(input_buffer_length.value as u64))]
    #[br(args(file_info_class, info_type))]
    #[bw(write_with = PosMarker::write_aoff_size_a, args(&_input_buffer_offset, &input_buffer_length, (*file_info_class, *info_type)))]
    buffer: QueryInfoRequestBuffer,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u8))]
pub enum QueryInfoType {
    File = 0x1,
    FileSystem = 0x2,
    Security = 0x3,
    Quota = 0x4,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct QueryAdditionalInfo {
    pub owner_security_information: bool,
    pub group_security_information: bool,
    pub dacl_security_information: bool,
    pub sacl_security_information: bool,

    pub label_security_information: bool,
    pub attribute_security_information: bool,
    pub scope_security_information: bool,

    #[skip]
    __: B9,
    pub backup_security_information: bool,
    #[skip]
    __: B15,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct QueryInfoFlags {
    pub restart_scan: bool,
    pub return_single_entry: bool,
    pub index_specified: bool,
    #[skip]
    __: B29,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(import(file_info_class: FileInfoClass, query_info_type: QueryInfoType))]
pub enum QueryInfoRequestBuffer {
    #[br(pre_assert(query_info_type == QueryInfoType::File))]
    QuotaInfo(QueryQuotaInfo),

    #[br(pre_assert(file_info_class == FileInfoClass::FullEaInformation && query_info_type == QueryInfoType::File))]
    EaInfo(GetEaInfoList),

    // Other cases have no buffer.
    None(()),
}

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryQuotaInfo {
    return_single: u8,
    restart_scan: u8,
    reserved: u16,
    sid_list_length: u32,  // type 1: list of FileGetQuotaInformation structs.
    start_sid_length: u32, // type 2: SIDs list
    start_sid_offset: u32,
    #[br(count = sid_list_length.max(start_sid_length))] // TODO: differentiate to t1/t2.
    sid_buffer: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct GetEaInfoList {
    #[br(parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = FileGetEaInformation::write_list)]
    values: Vec<FileGetEaInformation>,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryInfoResponse {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packets::smb2::plain::{tests as plain_tests, Content};

    use super::*;

    #[test]
    pub fn test_query_info_req_short_write() {
        let data = plain_tests::encode_content(Content::QueryInfoRequest(QueryInfoRequest {
            info_type: QueryInfoType::File,
            file_info_class: FileInfoClass::NetworkOpenInformation,
            output_buffer_length: 56,
            additional_information: QueryAdditionalInfo::new(),
            flags: QueryInfoFlags::new(),
            file_id: [
                0x77, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xc5, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0,
            ]
            .into(),
            buffer: QueryInfoRequestBuffer::None(()),
        }));
        assert_eq!(
            data,
            [
                0x29, 0x0, 0x1, 0x22, 0x38, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x77, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0,
                0xc5, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0
            ]
        )
    }

    #[test]
    pub fn test_query_info_ea_request() {
        let req = QueryInfoRequest {
            info_type: QueryInfoType::File,
            file_info_class: FileInfoClass::FullEaInformation,
            additional_information: QueryAdditionalInfo::new(),
            flags: QueryInfoFlags::new()
                .with_restart_scan(true)
                .with_return_single_entry(true),
            file_id: [
                0x7a, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xd1, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0,
            ]
            .into(),
            buffer: QueryInfoRequestBuffer::EaInfo(GetEaInfoList {
                values: vec![FileGetEaInformation::new("$MpEa_D262AC624451295")],
            }),
            output_buffer_length: 554,
        };
        let content_data = plain_tests::encode_content(Content::QueryInfoRequest(req));
        assert_eq!(
            content_data,
            [
                0x29, 0x0, 0x1, 0xf, 0x2a, 0x2, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x7a, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0,
                0xd1, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d,
                0x70, 0x45, 0x61, 0x5f, 0x44, 0x32, 0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34,
                0x35, 0x31, 0x32, 0x39, 0x35, 0x0
            ]
        )
    }
}
