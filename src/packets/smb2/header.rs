use binrw::prelude::*;
use modular_bitfield::prelude::*;

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum Command {
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u32))]
pub enum Status {
    Success = 0x00000000,
    Pending = 0x00000103,
    InvalidSmb = 0x00010002,
    SmbBadTid = 0x00050002,
    SmbBadCommand = 0x00160002,
    SmbBadUid = 0x005B0002,
    SmbUseStandard = 0x00FB0002,
    BufferOverflow = 0x80000005,
    NoMoreFiles = 0x80000006,
    StoppedOnSymlink = 0x8000002D,
    NotImplemented = 0xC0000002,
    InvalidParameter = 0xC000000D,
    NoSuchDevice = 0xC000000E,
    InvalidDeviceRequest0,
    MoreProcessingRequired = 0xC0000016,
    AccessDenied = 0xC0000022,
    BufferTooSmall = 0xC0000023,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
    ObjectPathNotFound = 0xC000003A,
    BadImpersonationLevel = 0xC00000A5,
    IoTimeout = 0xC00000B5,
    FileIsADirectory = 0xC00000BA,
    NotSupported = 0xC00000BB,
    NetworkNameDeleted = 0xC00000C9,
    UserSessionDeleted = 0xC0000203,
    NetworkSessionExpired = 0xC000035C,
    SmbTooManyUids = 0xC000205A,
}

#[binrw::binrw]
#[derive(Debug, Clone)]
#[brw(magic(b"\xfeSMB"), little)]
pub struct Header {
    #[bw(calc = Self::STRUCT_SIZE as u16)]
    #[br(assert(_structure_size == Self::STRUCT_SIZE as u16))]
    _structure_size: u16,
    pub credit_charge: u16,
    pub status: Status,
    pub command: Command,
    pub credit_request: u16,
    pub flags: HeaderFlags,
    pub next_command: u32,
    pub message_id: u64,
    #[bw(calc = 0)]
    _reserved: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: u128,
}

impl Header {
    pub const STRUCT_SIZE: usize = 64;
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct HeaderFlags {
    pub server_to_redir: bool,
    pub async_command: bool,
    pub related_operations: bool,
    pub signed: bool,
    pub priority_mask: B3,
    #[skip]
    __: B21,
    pub dfs_operations: bool,
    pub replay_operation: bool,
    #[skip]
    __: B2,
}
