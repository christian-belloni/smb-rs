// use super::ndr64::*;
// use binrw::prelude::*;

// #[binrw::binrw]
// #[derive(Debug, PartialEq, Eq)]
// pub enum ShareEnumStruct {
//     #[brw(magic = 1u32)]
//     Info1(ShareInfo1Container),
// }

// #[binrw::binrw]
// #[derive(Debug, PartialEq, Eq)]
// pub struct ShareInfo1Container {
//     entries_read: NdrAlign<u32>,
//     buffer: NdrArray<ShareInfo1, (), ()>,
// }

// #[binrw::binrw]
// #[derive(Debug, PartialEq, Eq)]
// pub struct ShareInfo1 {
//     netname: NdrPtr<NdrString<u16>>,
//     type_: NdrAlign<u32>,
//     remark: NdrPtr<NdrString<u16>>,
// }

// #[binrw::binrw]
// #[derive(Debug, PartialEq, Eq)]
// pub struct NetrShareEnumIn {
//     server_name: NdrPtr<NdrString<u16>>,
//     info_struct: ShareEnumStruct,
//     prefered_maximum_length: NdrAlign<u32>,
//     resume_handle: NdrPtr<u32>,
// }

// #[binrw::binrw]
// #[derive(Debug, PartialEq, Eq)]
// pub struct NetrShareEnumOut {
//     info_struct: ShareEnumStruct,
//     total_entries: NdrAlign<u32>,
//     resume_handle: NdrPtr<u32>,
// }
