//! MS-DTYP 2.4.5: ACL

use binrw::prelude::*;

use crate::packets::binrw_util::prelude::*;

use super::ACE;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ACL {
    pub acl_revision: AclRevision,
    #[bw(calc = 0)]
    #[br(assert(sbz1 == 0))]
    sbz1: u8,
    #[bw(calc = PosMarker::default())]
    _acl_size: PosMarker<u16>,
    #[bw(calc = ace.len() as u16)]
    ace_count: u16,
    #[bw(calc = 0)]
    #[br(assert(sbz2 == 0))]
    sbz2: u16,
    #[br(count = ace_count)]
    #[bw(write_with = PosMarker::write_size, args(&_acl_size))]
    pub ace: Vec<ACE>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum AclRevision {
    /// Windows NT 4.0
    Nt4 = 2,
    /// Active directory
    DS = 4,
}
