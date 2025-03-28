use std::io::Cursor;

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

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_as_string = match self {
            Command::Negotiate => "Negotiate",
            Command::SessionSetup => "Session Setup",
            Command::Logoff => "Logoff",
            Command::TreeConnect => "Tree Connect",
            Command::TreeDisconnect => "Tree Disconnect",
            Command::Create => "Create",
            Command::Close => "Close",
            Command::Flush => "Flush",
            Command::Read => "Read",
            Command::Write => "Write",
            Command::Lock => "Lock",
            Command::Ioctl => "Ioctl",
            Command::Cancel => "Cancel",
            Command::Echo => "Echo",
            Command::QueryDirectory => "Query Directory",
            Command::ChangeNotify => "Change Notify",
            Command::QueryInfo => "Query Info",
            Command::SetInfo => "Set Info",
            Command::OplockBreak => "Oplock Break",
        };
        write!(f, "{} ({:#x})", message_as_string, *self as u16)
    }
}

/// NT Status codes.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u32))]
pub enum Status {
    Success = 0x00000000,
    Pending = 0x00000103,
    NotifyCleanup = 0x0000010B,
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
    InvalidDeviceRequest0 = 0xC0000010,
    EndOfFile = 0xC0000011,
    MoreProcessingRequired = 0xC0000016,
    AccessDenied = 0xC0000022,
    BufferTooSmall = 0xC0000023,
    ObjectNameInvalid = 0xC0000033,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
    ObjectPathNotFound = 0xC000003A,
    LogonFailure = 0xC000006D,
    BadImpersonationLevel = 0xC00000A5,
    IoTimeout = 0xC00000B5,
    FileIsADirectory = 0xC00000BA,
    NotSupported = 0xC00000BB,
    NetworkNameDeleted = 0xC00000C9,
    BadNetworkName = 0xC00000CC,
    DirectoryNotEmpty = 0xC0000101,
    Cancelled = 0xC0000120,
    UserSessionDeleted = 0xC0000203,
    UserAccountLockedOut = 0xC0000234,
    NetworkSessionExpired = 0xC000035C,
    SmbTooManyUids = 0xC000205A,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_as_string = match self {
            Status::Success => "Success",
            Status::Pending => "Pending",
            Status::NotifyCleanup => "Notify Cleanup",
            Status::InvalidSmb => "Invalid SMB",
            Status::SmbBadTid => "SMB Bad TID",
            Status::SmbBadCommand => "SMB Bad Command",
            Status::SmbBadUid => "SMB Bad UID",
            Status::SmbUseStandard => "SMB Use Standard",
            Status::BufferOverflow => "Buffer Overflow",
            Status::NoMoreFiles => "No More Files",
            Status::StoppedOnSymlink => "Stopped on Symlink",
            Status::NotImplemented => "Not Implemented",
            Status::InvalidParameter => "Invalid Parameter",
            Status::NoSuchDevice => "No Such Device",
            Status::InvalidDeviceRequest0 => "Invalid Device Request",
            Status::EndOfFile => "End of File",
            Status::MoreProcessingRequired => "More Processing Required",
            Status::AccessDenied => "Access Denied",
            Status::BufferTooSmall => "Buffer Too Small",
            Status::ObjectNameInvalid => "Object Name Invalid",
            Status::ObjectNameNotFound => "Object Name Not Found",
            Status::ObjectNameCollision => "Object Name Collision",
            Status::ObjectPathNotFound => "Object Path Not Found",
            Status::LogonFailure => "Logon Failure",
            Status::BadImpersonationLevel => "Bad Impersonation Level",
            Status::IoTimeout => "I/O Timeout",
            Status::FileIsADirectory => "File is a Directory",
            Status::NotSupported => "Not Supported",
            Status::NetworkNameDeleted => "Network Name Deleted",
            Status::BadNetworkName => "Bad Network Name",
            Status::DirectoryNotEmpty => "Directory Not Empty",
            Status::Cancelled => "Cancelled",
            Status::UserAccountLockedOut => "User Account Locked Out",
            Status::UserSessionDeleted => "User Session Deleted",
            Status::NetworkSessionExpired => "Network Session Expired",
            Status::SmbTooManyUids => "SMB Too Many UIDs",
        };
        write!(f, "{} ({:#x})", message_as_string, *self as u32)
    }
}

impl Status {
    /// A helper function that tries converting u32 to a [`Status`],
    /// and returns a string representation of the status. Otherwise,
    /// it returns the hex representation of the u32 value.
    /// This is useful for displaying NT status codes that are not necessarily
    /// defined in the [`Status`] enum.
    pub fn try_display_as_status(value: u32) -> String {
        match Self::try_from(value) {
            Ok(status) => format!("{}", status),
            Err(_) => format!("{:#06x}", value),
        }
    }
}

impl TryFrom<u32> for Status {
    type Error = crate::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Status::read_le(&mut Cursor::new(value.to_le_bytes())).map_err(|_| {
            crate::Error::InvalidMessage(format!("NT Status code variant not found: {:#x}", value))
        })
    }
}

/// Sync and Async SMB2 Message header.
///
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(magic(b"\xfeSMB"), little)]
pub struct Header {
    #[bw(calc = Self::STRUCT_SIZE as u16)]
    #[br(assert(_structure_size == Self::STRUCT_SIZE as u16))]
    _structure_size: u16,
    pub credit_charge: u16,
    /// NT status. Use the [`Header::status()`] method to convert to a [`Status`].
    pub status: u32,
    pub command: Command,
    pub credit_request: u16,
    pub flags: HeaderFlags,
    pub next_command: u32,
    pub message_id: u64,

    // Option 1 - Sync: Reserved + TreeId. flags.async_command MUST NOT be set.
    #[brw(if(!flags.async_command()))]
    #[bw(calc = 0)]
    _reserved: u32,
    #[br(if(!flags.async_command()))]
    #[bw(assert(tree_id.is_some() == !flags.async_command()))]
    pub tree_id: Option<u32>,

    // Option 2 - Async: AsyncId. flags.async_command MUST be set manually.
    #[brw(if(flags.async_command()))]
    #[bw(assert(tree_id.is_none() == flags.async_command()))]
    pub async_id: Option<u64>,

    pub session_id: u64,
    pub signature: u128,
}

impl Header {
    pub const STRUCT_SIZE: usize = 64;

    /// Tries to convert the [`Header::status`] field to a [`Status`],
    /// returning it, if successful.
    pub fn status(&self) -> crate::Result<Status> {
        self.status.try_into()
    }
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    pub fn test_async_header_parse() {
        let arr = &[
            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x0, 0x0, 0x3, 0x1, 0x0, 0x0, 0xf, 0x0, 0x1, 0x0,
            0x13, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd7, 0x27, 0x53, 0x8, 0x0, 0x0, 0x0, 0x0, 0x63,
            0xf8, 0x25, 0xde, 0xae, 0x2, 0x95, 0x2f, 0xa3, 0xd8, 0xc8, 0xaa, 0xf4, 0x6e, 0x7c,
            0x99,
        ];
        let mut cursor = Cursor::new(arr);
        let header = Header::read_le(&mut cursor).unwrap();
        assert_eq!(
            header,
            Header {
                credit_charge: 0,
                status: Status::Pending as u32,
                command: Command::ChangeNotify,
                credit_request: 1,
                flags: HeaderFlags::new()
                    .with_async_command(true)
                    .with_server_to_redir(true)
                    .with_priority_mask(1),
                next_command: 0,
                message_id: 8,
                tree_id: None,
                async_id: Some(8),
                session_id: 0x00000000085327d7,
                signature: u128::from_le_bytes(u128::to_be_bytes(
                    0x63f825deae02952fa3d8c8aaf46e7c99
                )),
            }
        )
    }
}
