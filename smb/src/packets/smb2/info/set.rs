//! SMB2 Set Info Request/Response messages.

use super::super::{
    super::{binrw_util::prelude::*, guid::Guid},
    fscc::*,
};
use super::common::*;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SetInfoRequest {
    #[bw(calc = 33)]
    #[br(assert(_structure_size == 33))]
    _structure_size: u16,
    pub info_type: InfoType,
    pub info_class: SetFileInfoClass,
    #[bw(calc = PosMarker::default())]
    buffer_length: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _buffer_offset: PosMarker<u16>,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub additional_information: AdditionalInfo,
    pub file_id: Guid,
    #[br(map_stream = |s| s.take_seek(buffer_length.value as u64))]
    #[br(args(info_type))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_buffer_offset, &buffer_length))]
    pub data: SetInfoData,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SetInfoResponse {
    #[bw(calc = 2)]
    #[br(assert(_structure_size == 2))]
    _structure_size: u16,
}

#[binrw::binrw]
#[derive(Debug)]
#[br(import(info_type: InfoType))]
pub enum SetInfoData {
    #[br(pre_assert(info_type == InfoType::File))]
    File(RawSetFileInfo),
    #[br(pre_assert(info_type == InfoType::FileSystem))]
    FileSystem(InfoFilesystem),
    #[br(pre_assert(info_type == InfoType::Security))]
    Security(RawSecurityDescriptor),
    #[br(pre_assert(info_type == InfoType::Quota))]
    Quota(FileQuotaInformation),
}

impl SetInfoData {
    pub fn info_type(&self) -> InfoType {
        match self {
            SetInfoData::File(_) => InfoType::File,
            SetInfoData::FileSystem(_) => InfoType::FileSystem,
            SetInfoData::Security(_) => InfoType::Security,
            SetInfoData::Quota(_) => InfoType::Quota,
        }
    }

    pub fn to_req(self, info_class: SetFileInfoClass, file_id: Guid) -> SetInfoRequest {
        SetInfoRequest {
            info_type: self.info_type(),
            info_class: info_class,
            additional_information: AdditionalInfo::new(),
            file_id,
            data: self,
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct RawSetFileInfo {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl RawSetFileInfo {
    pub fn to_set_data(self) -> SetInfoData {
        SetInfoData::File(self)
    }

    pub fn parse(&self, class: SetFileInfoClass) -> Result<SetFileInfo, binrw::Error> {
        let mut cursor = std::io::Cursor::new(&self.data);
        SetFileInfo::read_args(&mut cursor, (class,))
    }
}

impl From<SetFileInfo> for RawSetFileInfo {
    fn from(value: SetFileInfo) -> Self {
        let mut cursor = std::io::Cursor::new(Vec::new());
        value.write(&mut cursor).unwrap();
        RawSetFileInfo {
            data: cursor.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packets::smb2::*;

    use super::*;

    #[test]
    fn test_set_info_request_write() {
        let set_info = SetFileInfo::RenameInformation(RenameInformation2 {
            replace_if_exists: false as u8,
            root_directory: 0,
            file_name: "hello\\myNewFile.txt".into(),
        });

        let cls = set_info.info_class();
        let req = RawSetFileInfo::from(set_info)
            .to_set_data()
            .to_req(cls, "00000042-000e-0000-0500-10000e000000".parse().unwrap());
        let req_data = encode_content(Content::SetInfoRequest(req));
        assert_eq!(
            req_data,
            [
                0x21, 0x0, 0x1, 0xa, 0x3a, 0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x42, 0x0, 0x0, 0x0, 0xe, 0x0, 0x0, 0x0, 0x5, 0x0, 0x10, 0x0, 0xe, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x26, 0x0, 0x0, 0x0, 0x68, 0x0, 0x65, 0x0, 0x6c, 0x0, 0x6c, 0x0, 0x6f, 0x0, 0x5c,
                0x0, 0x6d, 0x0, 0x79, 0x0, 0x4e, 0x0, 0x65, 0x0, 0x77, 0x0, 0x46, 0x0, 0x69, 0x0,
                0x6c, 0x0, 0x65, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0
            ]
        );
    }

    #[test]
    fn test_set_info_response_parse() {
        let data = [0x2, 0x0, 0x0, 0x0];
        let response = SetInfoResponse::read_le(&mut std::io::Cursor::new(&data)).unwrap();
        assert_eq!(response, SetInfoResponse {});
    }
}
