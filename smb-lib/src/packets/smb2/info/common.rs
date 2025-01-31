//! Common data structures for query/set info messages.


use super::super::security::*;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u8))]
pub enum InfoType {
    File = 0x1,
    FileSystem = 0x2,
    Security = 0x3,
    Quota = 0x4,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct AdditionalInfo {
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

/// TODO: Move to FSCC & implement properly.
#[binrw::binrw]
#[derive(Debug)]
pub struct InfoFilesystem {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct RawSecurityDescriptor {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl RawSecurityDescriptor {
    pub fn parse(
        &self,
        _additional_info: AdditionalInfo,
    ) -> Result<SecurityDescriptor, binrw::Error> {
        return Err(binrw::Error::Custom {
            pos: 0,
            err: Box::<String>::new("Not implemented!".into()),
        });
    }
}
