use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum SMB2Command {
    Negotiate = 00,
    SessionSetup = 01,
    Logoff = 02,
    TreeConnect = 03,
    TreeDisconnect = 04,
    Create = 05,
    Close = 06,
    Flush = 07,
    Read = 08,
    Write = 09,
    Lock = 0xA,
    Ioctl = 0xB,
    Cancel = 0xC,
    Echo = 0xD,
    QueryDirectory = 0xE,
    ChangeNotify = 0xF,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(magic(b"\xfeSMB"))]
pub struct SMB2MessageHeader {
    #[bw(calc = 64)]
    #[br(assert(_structure_size == 64))]
    _structure_size: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub command: SMB2Command,
    pub credit_request: u16,
    pub flags: SMB2HeaderFlags,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: u128
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SMB2HeaderFlags {
    pub server_to_redir: bool,
    pub async_command: bool,
    pub related_operations: bool,
    pub signed: bool,
    pub priority_mask: B3,
    _reserved1: B21,
    pub dfs_operations: bool,
    pub replay_operation: bool,
    _reserved2: B2,
}
