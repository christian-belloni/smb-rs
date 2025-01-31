use super::super::guid::Guid;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct OplockBreakMsg {
    #[bw(calc = 24)]
    #[br(assert(structure_size == 24))]
    structure_size: u16,
    oplock_level: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u32,
    file_id: Guid,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LeaseBreakNotify {
    #[bw(calc = 44)]
    #[br(assert(structure_size == 44))]
    structure_size: u16,
    new_epoch: u16,
    ack_required: u8,
    lease_key: Guid,
    current_lease_state: LeaseState,
    new_lease_state: LeaseState,
    #[bw(calc = 0)]
    #[br(assert(break_reason == 0))]
    break_reason: u32,
    #[bw(calc = 0)]
    #[br(assert(access_mask_hint == 0))]
    access_mask_hint: u32,
    #[bw(calc = 0)]
    #[br(assert(share_mask_hint == 0))]
    share_mask_hint: u32,
}

#[binrw::binrw]
#[brw(repr(u8))]
pub enum OplockLevel {
    None = 0,
    II = 1,
    Exclusive = 2,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct LeaseState {
    pub read_caching: bool,
    pub handle_caching: bool,
    pub write_caching: bool,
    #[skip]
    __: B29,
}

// Those are all the same.
pub type OplockBreakNotify = OplockBreakMsg;
pub type OplockBreakAck = OplockBreakMsg;
pub type OplockBreakResponse = OplockBreakMsg;

#[binrw::binrw]
#[derive(Debug)]
pub struct LeaseBreakAckResponse {
    #[bw(calc = 36)]
    #[br(assert(structure_size == 36))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
    #[bw(calc = 0)]  // reserved
    #[br(assert(flags == 0))]
    flags: u32,
    lease_key: Guid,
    lease_state: LeaseState,
    #[bw(calc = 0)]  // reserved
    #[br(assert(lease_duration == 0))]
    lease_duration: u64,
}

// Those are the same.
pub type LeaseBreakAck = LeaseBreakAckResponse;
pub type LeaseBreakResponse = LeaseBreakAckResponse;
