use super::super::guid::Guid;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct LockRequest {
    #[bw(calc = 48)]
    #[br(assert(structure_size == 48))]
    structure_size: u16,
    #[bw(try_calc = locks.len().try_into())]
    lock_count: u16,
    pub lock_sequence: LockSequence,
    pub file_id: Guid,
    #[br(count = lock_count)]
    pub locks: Vec<LockElement>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct LockSequence {
    pub number: B4,
    pub index: B28,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: LockFlag,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u32,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct LockFlag {
    pub shared: bool,
    pub exclusive: bool,
    pub unlock: bool,
    pub fail_immediately: bool,
    #[skip]
    __: B28,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct LockResponse {
    #[bw(calc = 4)]
    #[br(assert(structure_size == 4))]
    pub structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    pub reserved: u16,
}


#[cfg(test)]
pub mod tests {
    use super::*;

    // TODO: tests
}
