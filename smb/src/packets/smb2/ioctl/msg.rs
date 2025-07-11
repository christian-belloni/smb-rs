use super::{
    common::{IoctlBuffer, IoctlRequestContent},
    fsctl::*,
};
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use std::io::SeekFrom;

use crate::packets::{
    binrw_util::prelude::*,
    dfsc::{ReqGetDfsReferral, ReqGetDfsReferralEx, RespGetDfsReferral},
    smb2::FileId,
};

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct IoctlRequest {
    #[bw(calc = 57)]
    #[br(assert(struct_size == 57))]
    struct_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    _input_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _input_count: PosMarker<u32>,
    pub max_input_response: u32,
    #[bw(calc = 0)]
    #[br(assert(output_offset == 0))]
    output_offset: u32,
    #[bw(calc = 0)]
    #[br(assert(output_count == 0))]
    output_count: u32,
    pub max_output_response: u32,
    pub flags: IoctlRequestFlags,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u32,

    #[bw(write_with = PosMarker::write_aoff_size, args(&_input_offset, &_input_count))]
    #[br(map_stream = |s| s.take_seek(_input_count.value as u64), args(ctl_code, flags))]
    pub buffer: IoctlReqData,
}

/// This is a helper trait that defines, for a certain FSCTL request type,
/// the response type and their matching FSCTL code.
pub trait FsctlRequest: for<'a> BinWrite<Args<'a> = ()> + Into<IoctlReqData> {
    type Response: FsctlResponseContent;
    const FSCTL_CODE: FsctlCodes;
}

macro_rules! ioctl_req_data {
    ($($fsctl:ident: $model:ty, $response:ty, )+) => {
        paste::paste! {

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(ctl_code: u32, flags: IoctlRequestFlags))]
pub enum IoctlReqData {
    $(
        #[br(pre_assert(ctl_code == FsctlCodes::$fsctl as u32 && flags.is_fsctl()))]
        [<Fsctl $fsctl:camel>]($model),
    )+

    /// General Ioctl request, providing a buffer as an input.
    Ioctl(IoctlBuffer),
}

impl IoctlReqData {
    pub fn get_size(&self) -> u32 {
        use IoctlReqData::*;
        match self {
            $(
                [<Fsctl $fsctl:camel>](data) => data.get_bin_size(),
            )+
            Ioctl(data) => data.len() as u32,
        }
    }
}

$(
    impl FsctlRequest for $model {
        type Response = $response;
        const FSCTL_CODE: FsctlCodes = FsctlCodes::$fsctl;
    }

    impl From<$model> for IoctlReqData {
        fn from(model: $model) -> IoctlReqData {
            IoctlReqData::[<Fsctl $fsctl:camel>](model)
        }
    }
)+
        }
    }
}

// TODO: Enable non-fsctl ioctls. currently, we only support FSCTLs.
ioctl_req_data! {
    PipePeek: PipePeekRequest, PipePeekResponse,
    SrvEnumerateSnapshots: SrvEnumerateSnapshotsRequest, SrvEnumerateSnapshotsResponse,
    SrvRequestResumeKey: SrvRequestResumeKeyRequest, SrvRequestResumeKey,
    QueryNetworkInterfaceInfo: QueryNetworkInterfaceInfoRequest, NetworkInterfaceInfo,
    SrvCopychunk: SrvCopychunkCopy, SrvCopychunkResponse,
    SrvCopychunkWrite: SrvCopyChunkCopyWrite, SrvCopychunkResponse,
    SrvReadHash: SrvReadHashReq, SrvReadHashRes,
    LmrRequestResiliency: NetworkResiliencyRequest, LmrRequestResiliencyResponse,
    ValidateNegotiateInfo: ValidateNegotiateInfoRequest, ValidateNegotiateInfoResponse,
    DfsGetReferrals: ReqGetDfsReferral, RespGetDfsReferral,
    PipeWait: PipeWaitRequest, PipeWaitResponse,
    PipeTransceive: PipeTransceiveRequest, PipeTransceiveResponse,
    SetReparsePoint: SetReparsePointRequest, SetReparsePointResponse,
    DfsGetReferralsEx: ReqGetDfsReferralEx, RespGetDfsReferral,
    FileLevelTrim: FileLevelTrimRequest, FileLevelTrimResponse,
    QueryAllocatedRanges: QueryAllocRangesItem, QueryAllocRangesResult,
    OffloadRead: OffloadReadRequest, OffloadReadResponse,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct IoctlRequestFlags {
    pub is_fsctl: bool,
    #[skip]
    __: B31,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct IoctlResponse {
    #[bw(calc = 49)]
    #[br(assert(struct_size == 49))]
    struct_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    input_offset: PosMarker<u32>,
    #[bw(assert(out_buffer.is_empty()))] // there is an exception for pass-through operations.
    #[bw(try_calc = in_buffer.len().try_into())]
    #[br(assert(input_count == 0))]
    input_count: u32,

    // is either (0) or (input_offset + input_count)
    #[br(assert(output_offset.value == 0 || output_offset.value == input_offset.value + input_count))]
    #[bw(calc = PosMarker::default())]
    output_offset: PosMarker<u32>,
    #[bw(try_calc = out_buffer.len().try_into())]
    output_count: u32,

    #[bw(calc = 0)] // reserved.
    #[br(assert(flags == 0))]
    flags: u32,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u32,

    #[br(seek_before = SeekFrom::Start(input_offset.value.into()))]
    #[br(count = input_count)]
    pub in_buffer: Vec<u8>,

    #[br(seek_before = SeekFrom::Start(output_offset.value.into()))]
    #[br(count = output_count)]
    pub out_buffer: Vec<u8>,
}

impl IoctlResponse {
    /// Parses the response content into the specified type.
    pub fn parse_fsctl<T>(&self) -> crate::Result<T>
    where
        T: FsctlResponseContent,
    {
        if !T::FSCTL_CODES.iter().any(|&f| f as u32 == self.ctl_code) {
            return Err(crate::Error::InvalidArgument(format!(
                "The type {} is not valid for FSCTL {}!",
                std::any::type_name::<T>(),
                self.ctl_code
            )));
        }
        let mut cursor = std::io::Cursor::new(&self.out_buffer);
        Ok(T::read_le(&mut cursor).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::packets::smb2::*;

    use super::*;

    #[test]
    pub fn test_ioctl_req_write() {
        let encoded = encode_content(
            IoctlRequest {
                ctl_code: FsctlCodes::PipeTransceive as u32,
                file_id: [
                    0x28, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x85, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0,
                    0x0,
                ]
                .into(),
                max_input_response: 0,
                max_output_response: 1024,
                flags: IoctlRequestFlags::new().with_is_fsctl(true),
                buffer: IoctlReqData::FsctlPipeTransceive(
                    Into::<IoctlBuffer>::into(
                        [
                            0x5, 0x0, 0x0, 0x3, 0x10, 0x0, 0x0, 0x0, 0x98, 0x0, 0x0, 0x0, 0x3, 0x0,
                            0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x1, 0x0, 0x39, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x13, 0xf8, 0xa5, 0x8f, 0x16, 0x6f, 0xb5, 0x44, 0x82, 0xc2, 0x8f, 0x2d,
                            0xae, 0x14, 0xd, 0xf5, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95, 0x56, 0x53,
                            0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x2, 0x0, 0x0, 0x0,
                        ]
                        .as_ref(),
                    )
                    .into(),
                ),
            }
            .into(),
        );
        assert_eq!(
            encoded,
            &[
                0x39, 0x0, 0x0, 0x0, 0x17, 0xc0, 0x11, 0x0, 0x28, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0,
                0x0, 0x85, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x98, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0,
                0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x3, 0x10, 0x0, 0x0,
                0x0, 0x98, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x1, 0x0, 0x39,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x13, 0xf8, 0xa5, 0x8f, 0x16, 0x6f, 0xb5, 0x44, 0x82,
                0xc2, 0x8f, 0x2d, 0xae, 0x14, 0xd, 0xf5, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0,
                0x17, 0x3d, 0xa7, 0x2e, 0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x2, 0x0, 0x0, 0x0
            ]
        )
    }

    #[test]
    pub fn test_ioctl_res_parse() {
        let data = [
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb, 0x0, 0x1, 0x0,
            0x31, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff,
            0xfe, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x31, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x31, 0x0,
            0x0, 0x0, 0x17, 0xc0, 0x11, 0x0, 0x28, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x85, 0x0,
            0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x0, 0x0,
            0x0, 0x4, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, 0x3,
            0x10, 0x0, 0x0, 0x0, 0x4, 0x1, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0xec, 0x0, 0x0, 0x0, 0x1,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0,
            0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x4, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95, 0x56, 0x53,
            0xf9, 0x15, 0xdf, 0xf2, 0x80, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x61, 0x0, 0x76, 0x0, 0x69, 0x0, 0x76, 0x0, 0x6e, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let message = decode_content(&data);
        let message = message.content.to_ioctl().unwrap();
        assert_eq!(
            message,
            IoctlResponse {
                ctl_code: FsctlCodes::PipeTransceive as u32,
                file_id: [
                    0x28, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x85, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0,
                    0x0,
                ]
                .into(),
                in_buffer: vec![],
                out_buffer: [
                    0x5, 0x0, 0x2, 0x3, 0x10, 0x0, 0x0, 0x0, 0x4, 0x1, 0x0, 0x0, 0x3, 0x0, 0x0,
                    0x0, 0xec, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0xc, 0x0, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x41, 0x0, 0x56, 0x0, 0x49, 0x0, 0x56, 0x0, 0x56, 0x0, 0x4d,
                    0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x4, 0x0,
                    0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95,
                    0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x61, 0x0, 0x76, 0x0, 0x69, 0x0,
                    0x76, 0x0, 0x6e, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                ]
                .to_vec(),
            }
        );
    }
}
