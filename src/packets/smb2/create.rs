use std::io::SeekFrom;

use super::fscc::*;
use crate::binrw_util::SizedWideString;
use crate::pos_marker::PosMarker;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2CreateRequest {
    #[bw(calc = 57)]
    #[br(assert(structure_size == 57))]
    structure_size: u16,
    #[bw(calc = 0)] // reserved
    #[br(assert(_security_flags == 0))]
    _security_flags: u8,
    pub requested_oplock_level: OplockLevel,
    pub impersonation_level: ImpersonationLevel,
    pub smb_create_flags: u64,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u64,
    pub desired_access: FileAccessMask,
    pub file_attributes: FileAttributes,
    pub share_access: SMB2ShareAccessFlags,
    pub create_disposition: CreateDisposition,
    pub create_options: u32,
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(try_calc = name.size().try_into())]
    name_length: u16, // bytes
    #[bw(calc = PosMarker::default())]
    _create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _create_contexts_length: PosMarker<u32>,

    #[brw(align_before = 8)]
    #[bw(write_with = PosMarker::write_and_fill_start_offset, args(&_name_offset))]
    #[br(args(name_length as u64))]
    pub name: SizedWideString,

    #[brw(align_before = 8)]
    #[br(map_stream = |s| s.take_seek(_create_contexts_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = SMB2CreateContext::write_list, args(&_create_contexts_offset, &_create_contexts_length))]
    pub contexts: Vec<SMB2CreateContext<true>>,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u32))]
pub enum ImpersonationLevel {
    Anonymous = 0x0,
    Identification = 0x1,
    Impersonation = 0x2,
    Delegate = 0x3,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u32))]
pub enum CreateDisposition {
    Superseded = 0x0,
    Open = 0x1,
    Create = 0x2,
    OpenIf = 0x3,
    Overwrite = 0x4,
    OverwriteIf = 0x5,
}

// share_access 4 byte flags:
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SMB2ShareAccessFlags {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    #[skip]
    __: B29,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SMB2CreateResponse {
    #[bw(calc = 89)]
    #[br(assert(structure_size == 89))]
    structure_size: u16,
    pub oplock_level: OplockLevel,
    // always 1 or 0, depends on dialect.
    #[br(assert(flags == 0 || flags == 1))]
    #[bw(assert(*flags == 0 || *flags == 1))]
    pub flags: u8,
    pub create_action: CreateAction,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,
    pub file_id: u128,
    // assert it's 8-aligned
    #[br(assert(create_contexts_offset.value & 0x7 == 0))]
    #[bw(calc = PosMarker::default())]
    create_contexts_offset: PosMarker<u32>, // from smb header start
    #[bw(calc = PosMarker::default())]
    create_contexts_length: PosMarker<u32>, // bytes
    #[br(seek_before = SeekFrom::Start(create_contexts_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(create_contexts_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = SMB2CreateContext::write_list, args(&create_contexts_offset, &create_contexts_length))]
    pub create_contexts: Vec<SMB2CreateContext<false>>,
}

impl SMB2CreateResponse {
    pub fn maximal_access_context(&self) -> Option<&MxAcResp> {
        self.create_contexts.iter().find_map(|c| match &c.data {
            CreateContextData::MxAcResp(r) => Some(r),
            _ => None,
        })
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum OplockLevel {
    None = 0,
    II = 1,
    Exclusive = 8,
    Batch = 9,
    Lease = 0xff,
}

// CreateAction
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum CreateAction {
    Superseded = 0x0,
    Opened = 0x1,
    Created = 0x2,
    Overwritten = 0x3,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(has_next: bool))]
pub struct SMB2CreateContext<const IS_REQUEST: bool> {
    #[bw(calc = PosMarker::default())]
    _next: PosMarker<u32>, // from current location
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(name.len()).unwrap())]
    name_length: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
    #[bw(calc = PosMarker::default())]
    _data_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    _data_length: PosMarker<u32>,
    #[brw(align_before = 8)]
    #[br(count = name_length)]
    #[bw(write_with = PosMarker::write_and_fill_offset_with_base, args(&_name_offset, &_next))]
    pub name: Vec<u8>,
    #[brw(align_before = 8)]
    #[bw(write_with = PosMarker::write_and_fill_offset_and_size_with_base_args, args(&_data_offset, &_data_length, &_next, (name,)))]
    #[br(args(&name))]
    pub data: CreateContextData<IS_REQUEST>,

    // The following value writes next if has_next is true,
    #[bw(if(has_next))]
    // Fill the next offset
    // and also make sure to align to 8 bytes right afterwords.
    #[bw(align_before = 8)]
    #[bw(write_with = PosMarker::write_and_fill_relative_offset, args(&_next))]
    // When reading, move the stream to the next context if there is one.
    #[br(seek_before = _next.seek_relative(true))]
    fill_next: (),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(import(name: &Vec<u8>))]
pub enum CreateContextData<const IS_REQUEST: bool> {
    #[br(pre_assert(IS_REQUEST && name.as_slice() == Self::DH2Q))]
    #[bw(assert(IS_REQUEST && name.as_slice() == Self::DH2Q))]
    DH2QReq(DH2QReq),
    #[br(pre_assert(IS_REQUEST && name.as_slice() == Self::MxAc))]
    #[bw(assert(IS_REQUEST && name.as_slice() == Self::MxAc))]
    MxAcReq(()),
    #[br(pre_assert(IS_REQUEST && name.as_slice() == Self::QFid))]
    #[bw(assert(IS_REQUEST && name.as_slice() == Self::QFid))]
    QFidReq(()),

    #[br(pre_assert(!IS_REQUEST && name.as_slice() == Self::DH2Q))]
    #[bw(assert(!IS_REQUEST && name.as_slice() == Self::DH2Q))]
    DH2QResp(DH2QResp),
    #[br(pre_assert(!IS_REQUEST && name.as_slice() == Self::MxAc))]
    #[bw(assert(!IS_REQUEST && name.as_slice() == Self::MxAc))]
    MxAcResp(MxAcResp),
    #[br(pre_assert(!IS_REQUEST && name.as_slice() == Self::QFid))]
    #[bw(assert(!IS_REQUEST && name.as_slice() == Self::QFid))]
    QFidResp(QFidResp),

    Empty(()),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DH2QReq {
    pub timeout: u32,
    pub flags: u32,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u64,
    pub create_guid: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct MxAcResp {
    pub query_status: u32,
    pub maximal_access: FileAccessMask,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QFidResp {
    pub file_id: u64,
    pub volume_id: u64,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DH2QResp {
    pub timeout: u32,
    pub flags: u32,
}

impl<const T: bool> SMB2CreateContext<T> {
    pub fn new(data: CreateContextData<T>) -> SMB2CreateContext<T> {
        SMB2CreateContext {
            name: data.name().to_vec(),
            data,
            fill_next: (),
        }
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
    fn write_list(
        contexts: &Vec<SMB2CreateContext<T>>,
        offset_dest: &PosMarker<u32>,
        size_bytes_dest: &PosMarker<u32>,
    ) -> BinResult<()> {
        // 1.a. write start offset and get back to the end of the file
        let start_offset = offset_dest.do_writeback_offset(writer, endian)?;

        // 2. write the list, pass on `has_next`
        for (i, context) in contexts.iter().enumerate() {
            let has_next = i != contexts.len() - 1; // not last?
            context.write_options(writer, endian, (has_next,))?;
        }

        // 2.b. write size of the list
        let size_bytes = writer.stream_position()? - start_offset;
        size_bytes_dest.do_writeback(size_bytes, writer, endian)?;
        Ok(())
    }
}

impl<const T: bool> CreateContextData<T> {
    const DH2Q: &[u8] = b"DH2Q";
    const MxAc: &[u8] = b"MxAc";
    const QFid: &[u8] = b"QFid";

    pub fn name(&self) -> &[u8] {
        match T {
            false => match self {
                CreateContextData::DH2QResp(_) => Self::DH2Q,
                CreateContextData::MxAcResp(_) => Self::MxAc,
                CreateContextData::QFidResp(_) => Self::QFid,
                _ => panic!("Invalid context type"),
            },
            true => match self {
                CreateContextData::DH2QReq(_) => Self::DH2Q,
                CreateContextData::MxAcReq(_) => Self::MxAc,
                CreateContextData::QFidReq(_) => Self::QFid,
                _ => panic!("Invalid context type"),
            },
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2CloseRequest {
    #[bw(calc = 24)]
    #[br(assert(_structure_size == 24))]
    _structure_size: u16,
    #[bw(calc = CloseFlags::new().with_postquery_attrib(true))] // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    #[br(assert(_flags == CloseFlags::new().with_postquery_attrib(true)))]
    _flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    pub file_id: u128,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct SMB2CloseResponse {
    #[bw(calc = 60)]
    #[br(assert(_structure_size == 60))]
    _structure_size: u16,
    pub flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct CloseFlags {
    pub postquery_attrib: bool,
    #[skip]
    __: B15,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::packets::smb2::{
        header::SMB2MessageHeader,
        message::{SMB2Message, SMBMessageContent},
    };

    use super::*;

    #[test]
    pub fn test_create_request_written_correctly() {
        let file_name = "hello";
        let request = SMB2CreateRequest {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            smb_create_flags: 0,
            desired_access: FileAccessMask::from_bytes(0x00100081u32.to_le_bytes()),
            file_attributes: FileAttributes::new(),
            share_access: SMB2ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true),
            create_disposition: CreateDisposition::Open,
            create_options: 0x00020020,
            name: file_name.into(),
            contexts: vec![
                SMB2CreateContext::new(CreateContextData::DH2QReq(DH2QReq {
                    timeout: 0,
                    flags: 0,
                    create_guid: 0x821680290c007b8b11efc0a0c679a320,
                })),
                SMB2CreateContext::new(CreateContextData::MxAcReq(())),
                SMB2CreateContext::new(CreateContextData::QFidReq(())),
            ],
        };

        let mut data = Vec::new();
        SMB2Message::new(SMBMessageContent::SMBCreateRequest(request))
            .write(&mut Cursor::new(&mut data))
            .unwrap();
        let data_without_header = &data[SMB2MessageHeader::STRUCT_SIZE..];
        assert!(
            data_without_header
                == vec![
                    0x39, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x81, 0x0, 0x10, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x20, 0x0, 0x2, 0x0, 0x78,
                    0x0, 0xa, 0x0, 0x88, 0x0, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x68, 0x0, 0x65, 0x0,
                    0x6c, 0x0, 0x6c, 0x0, 0x6f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0,
                    0x0, 0x10, 0x0, 0x4, 0x0, 0x0, 0x0, 0x18, 0x0, 0x20, 0x0, 0x0, 0x0, 0x44, 0x48,
                    0x32, 0x51, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0xa3, 0x79, 0xc6, 0xa0, 0xc0, 0xef,
                    0x11, 0x8b, 0x7b, 0x0, 0xc, 0x29, 0x80, 0x16, 0x82, 0x18, 0x0, 0x0, 0x0, 0x10,
                    0x0, 0x4, 0x0, 0x0, 0x0, 0x18, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4d, 0x78, 0x41, 0x63,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x4, 0x0, 0x0, 0x0, 0x18,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x51, 0x46, 0x69, 0x64, 0x0, 0x0, 0x0, 0x0
                ]
        )
    }

    #[test]
    pub fn test_create_response_parsed_correctly() {
        let data: [u8; 240] = [
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x01, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x61, 0x00,
            0x00, 0x14, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x3c, 0x08, 0x38, 0x96, 0xae, 0x4b, 0xdb, 0x01, 0xc8, 0x55, 0x4b, 0x70,
            0x6b, 0x58, 0xdb, 0x01, 0x62, 0x0c, 0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x01, 0x62, 0x0c,
            0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x49, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x4d, 0x78, 0x41, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01,
            0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x00, 0x00, 0x00, 0x18, 0x00,
            0x20, 0x00, 0x00, 0x00, 0x51, 0x46, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x2a, 0xe7,
            0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0xd9, 0xcf, 0x17, 0xb0, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let m = match SMB2Message::read(&mut Cursor::new(&data)).unwrap().content {
            SMBMessageContent::SMBCreateResponse(m) => m,
            _ => panic!("Expected SMBCreateResponse"),
        };

        assert!(
            m == SMB2CreateResponse {
                oplock_level: OplockLevel::None,
                flags: 0,
                create_action: CreateAction::Opened,
                creation_time: 133783827154208828,
                last_access_time: 133797832406291912,
                last_write_time: 133783939554544738,
                change_time: 133783939554544738,
                allocation_size: 0,
                endof_file: 0,
                file_attributes: FileAttributes::new().with_directory(true),
                file_id: 950737950337192747837452976457,
                create_contexts: vec![
                    SMB2CreateContext::new(CreateContextData::MxAcResp(MxAcResp {
                        query_status: 0,
                        maximal_access: FileAccessMask::from_bytes(0x001f01ffu32.to_le_bytes()),
                    })),
                    SMB2CreateContext::new(CreateContextData::QFidResp(QFidResp {
                        file_id: 0x400000001e72a,
                        volume_id: 0xb017cfd9,
                    })),
                ]
            }
        )
    }
}
