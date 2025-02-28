//! Get/Set Info Request/Response

use crate::packets::smb2::SecurityDescriptor;
use binrw::{io::TakeSeekExt, prelude::*};
use modular_bitfield::prelude::*;
use paste::paste;
use std::io::{Cursor, SeekFrom};

use super::super::{super::binrw_util::prelude::*, super::guid::Guid, fscc::*};
use super::common::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryInfoRequest {
    #[bw(calc = 41)]
    #[br(assert(_structure_size == 41))]
    _structure_size: u16,
    pub info_type: InfoType,
    #[brw(args(info_type))]
    pub info_class: QueryInfoClass,

    pub output_buffer_length: u32,
    #[bw(calc = PosMarker::default())]
    _input_buffer_offset: PosMarker<u16>,
    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u16,
    #[bw(calc = PosMarker::default())]
    input_buffer_length: PosMarker<u32>,
    pub additional_information: AdditionalInfo,
    pub flags: QueryInfoFlags,
    pub file_id: Guid,
    #[br(map_stream = |s| s.take_seek(input_buffer_length.value as u64))]
    #[br(args(&info_class, info_type))]
    #[bw(write_with = PosMarker::write_aoff_size_a, args(&_input_buffer_offset, &input_buffer_length, (info_class, *info_type)))]
    pub data: GetInfoRequestData,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(info_type: InfoType))]
#[bw(import(info_type: &InfoType))]
pub enum QueryInfoClass {
    #[br(pre_assert(matches!(info_type, InfoType::File)))]
    #[bw(assert(matches!(info_type, InfoType::File)))]
    File(QueryFileInfoClass),
    #[br(pre_assert(matches!(info_type, InfoType::FileSystem)))]
    #[bw(assert(matches!(info_type, InfoType::FileSystem)))]
    FileSystem(QueryFileSystemInfoClass),
    Empty(NullByte),
}

impl Default for QueryInfoClass {
    fn default() -> Self {
        QueryInfoClass::Empty(NullByte {})
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NullByte {
    #[bw(calc = 0)]
    #[br(assert(_null == 0))]
    _null: u8,
}

impl AdditionalInfo {
    pub fn is_security(&self) -> bool {
        self.owner_security_information()
            || self.group_security_information()
            || self.dacl_security_information()
            || self.sacl_security_information()
            || self.label_security_information()
            || self.attribute_security_information()
            || self.scope_security_information()
            || self.backup_security_information()
    }
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
#[brw(import(file_info_class: &QueryInfoClass, query_info_type: InfoType))]
pub enum GetInfoRequestData {
    #[br(pre_assert(query_info_type == InfoType::File))]
    #[bw(assert(query_info_type == InfoType::File))]
    QuotaInfo(QueryQuotaInfo),

    #[br(pre_assert(matches!(file_info_class, QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)) && query_info_type == InfoType::File))]
    #[bw(assert(matches!(file_info_class, QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)) && query_info_type == InfoType::File))]
    EaInfo(GetEaInfoList),

    // Other cases have no data.
    None(()),
}

#[binrw::binrw]
#[derive(Debug)]
pub struct QueryQuotaInfo {
    return_single: u8,
    restart_scan: u8,
    _reserved: u16,
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
    #[bw(write_with = FileGetEaInformation::write_chained)]
    values: Vec<FileGetEaInformation>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryInfoResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    #[bw(calc = PosMarker::default())]
    output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    output_buffer_length: PosMarker<u32>,
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length.value.into()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&output_buffer_offset, &output_buffer_length))]
    data: QueryInfoResponseData,
}

impl QueryInfoResponse {
    pub fn parse(&self, info_type: InfoType) -> Result<QueryInfoData, binrw::Error> {
        self.data.parse(info_type)
    }
}

/// A helpers struct that contains the raw data of a query info response or a set info request,
/// and can be parsed using the [QueryInfoResponseData::parse] method, to a specific info type.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryInfoResponseData {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl QueryInfoResponseData {
    /// Call this method to parse the raw data into a specific info type.
    pub fn parse(&self, info_type: InfoType) -> Result<QueryInfoData, binrw::Error> {
        let mut cursor = Cursor::new(&self.data);
        QueryInfoData::read_args(&mut cursor, (info_type,))
    }
}

impl From<Vec<u8>> for QueryInfoResponseData {
    fn from(data: Vec<u8>) -> Self {
        QueryInfoResponseData { data }
    }
}

/// Internal helper macro to easily generate fields & methods for [QueryInfoData].
macro_rules! query_info_data {
    ($($info_type:ident: $content:ident, )+) => {
        paste! {
            /// Represents information passed in get/set info requests.
            /// This is the information matching [InfoType], and should be used
            /// in the get info response and in the set info request.
            #[binrw::binrw]
            #[derive(Debug)]
            #[brw(little)]
            #[br(import(info_type: InfoType))]
            pub enum QueryInfoData {
                $(
                    #[br(pre_assert(info_type == InfoType::$info_type))]
                    $info_type($content),
                )+
            }

            impl QueryInfoData {
                $(
                    pub fn [<unwrap_ $info_type:lower>](self) -> $content {
                        match self {
                            QueryInfoData::$info_type(data) => data,
                            _ => panic!("Expected $info_type, got {:?}", self),
                        }
                    }
                )+
            }
        }
    };
}

query_info_data! {
    File: QueryInfoFileRaw,
    FileSystem: QueryInfoRawFilesystem,
    Security: SecurityDescriptor,
    Quota: QueryQuotaInfo,
}

/// File information class for QueryInfoRequest.
#[binrw::binrw]
#[derive(Debug)]
pub struct QueryInfoFileRaw {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl QueryInfoFileRaw {
    /// Call this method to parse the raw data into a [QueryFileInfo] struct.
    ///
    /// This method requires [FileInfoClass] to be passed as an argument.
    pub fn parse(&self, class: QueryFileInfoClass) -> Result<QueryFileInfo, binrw::Error> {
        let mut cursor = Cursor::new(&self.data);
        QueryFileInfo::read_args(&mut cursor, (class,))
    }
}

/// Same for FileSystem:
#[binrw::binrw]
#[derive(Debug)]
pub struct QueryInfoRawFilesystem {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl QueryInfoRawFilesystem {
    pub fn parse(&self, class: QueryFileSystemInfoClass) -> Result<QueryFileSystemInfo, binrw::Error> {
        let mut cursor = Cursor::new(&self.data);
        QueryFileSystemInfo::read_args(&mut cursor, (class,))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use time::macros::datetime;

    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_query_info_req_short_write() {
        let data = encode_content(Content::QueryInfoRequest(QueryInfoRequest {
            info_type: InfoType::File,
            info_class: QueryInfoClass::File(QueryFileInfoClass::NetworkOpenInformation),
            output_buffer_length: 56,
            additional_information: AdditionalInfo::new(),
            flags: QueryInfoFlags::new(),
            file_id: [
                0x77, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xc5, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0,
            ]
            .into(),
            data: GetInfoRequestData::None(()),
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
            info_type: InfoType::File,
            info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
            additional_information: AdditionalInfo::new(),
            flags: QueryInfoFlags::new()
                .with_restart_scan(true)
                .with_return_single_entry(true),
            file_id: [
                0x7a, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xd1, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0,
            ]
            .into(),
            data: GetInfoRequestData::EaInfo(GetEaInfoList {
                values: vec![FileGetEaInformationInner {
                    ea_name: "$MpEa_D262AC624451295".into(),
                }
                .into()],
            }),
            output_buffer_length: 554,
        };
        let content_data = encode_content(Content::QueryInfoRequest(req));
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

    #[test]
    pub fn test_query_security_request() {
        let res = encode_content(Content::QueryInfoRequest(QueryInfoRequest {
            info_type: InfoType::Security,
            info_class: Default::default(),
            output_buffer_length: 0,
            additional_information: AdditionalInfo::new()
                .with_owner_security_information(true)
                .with_group_security_information(true)
                .with_dacl_security_information(true)
                .with_sacl_security_information(true),
            flags: QueryInfoFlags::new(),
            file_id: Guid::from_str("0000002b-000d-0000-3100-00000d000000").unwrap(),
            data: GetInfoRequestData::None(()),
        }));
        assert_eq!(
            res,
            &[
                0x29, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2b, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0,
                0x31, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0,
            ]
        );
    }

    #[test]
    pub fn test_query_info_resp_parse_basic() {
        let parsed = decode_content(&[
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x1, 0x0,
            0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x69, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x77,
            0x53, 0x6f, 0xb5, 0x9c, 0x21, 0xa4, 0xcd, 0x99, 0x9b, 0xc0, 0x87, 0xb9, 0x6, 0x83,
            0xa3, 0x9, 0x0, 0x48, 0x0, 0x28, 0x0, 0x0, 0x0, 0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58,
            0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51,
            0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0,
        ]);
        let parsed = match parsed.content {
            Content::QueryInfoResponse(x) => x,
            _ => panic!("Expected QueryInfoResponse, got {:?}", parsed),
        };
        assert_eq!(
            parsed,
            QueryInfoResponse {
                data: [
                    0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51,
                    0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1,
                    0xd, 0x51, 0x6b, 0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                ]
                .to_vec()
                .into(),
            }
        );
    }

    #[test]
    pub fn test_query_info_resp_parse_file() {
        let raw_data: QueryInfoResponseData = [
            0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb,
            0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b,
            0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]
        .to_vec()
        .into();
        assert_eq!(
            raw_data
                .parse(InfoType::File)
                .unwrap()
                .unwrap_file()
                .parse(QueryFileInfoClass::BasicInformation)
                .unwrap(),
            QueryFileInfo::BasicInformation(FileBasicInformation {
                creation_time: datetime!(2024-12-27 14:22:48.792994700).into(),
                last_access_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                last_write_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                change_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                file_attributes: FileAttributes::new().with_archive(true)
            })
        )
    }
}
