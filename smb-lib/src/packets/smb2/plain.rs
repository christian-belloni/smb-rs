use binrw::prelude::*;

use super::header::*;
use super::*;

#[derive(BinRead, BinWrite, Debug)]
#[brw(import(command: &Command, from_srv: bool))]
pub enum Content {
    // negotiate
    #[br(pre_assert(matches!(command, Command::Negotiate) && !from_srv))]
    NegotiateRequest(negotiate::NegotiateRequest),
    #[br(pre_assert(matches!(command, Command::Negotiate) && from_srv))]
    NegotiateResponse(negotiate::NegotiateResponse),

    // session setup
    #[br(pre_assert(matches!(command, Command::SessionSetup) && !from_srv))]
    SessionSetupRequest(session_setup::SessionSetupRequest),
    #[br(pre_assert(matches!(command, Command::SessionSetup) && from_srv))]
    SessionSetupResponse(session_setup::SessionSetupResponse),

    // logoff
    #[br(pre_assert(matches!(command, Command::Logoff) && !from_srv))]
    LogoffRequest(session_setup::LogoffRequest),
    #[br(pre_assert(matches!(command, Command::Logoff) && from_srv))]
    LogoffResponse(session_setup::LogoffResponse),

    // tree connect
    #[br(pre_assert(matches!(command, Command::TreeConnect) && !from_srv))]
    TreeConnectRequest(tree_connect::TreeConnectRequest),
    #[br(pre_assert(matches!(command, Command::TreeConnect) && from_srv))]
    TreeConnectResponse(tree_connect::TreeConnectResponse),

    // tree disconnect
    #[br(pre_assert(matches!(command, Command::TreeDisconnect) && !from_srv))]
    TreeDisconnectRequest(tree_connect::TreeDisconnectRequest),
    #[br(pre_assert(matches!(command, Command::TreeDisconnect) && from_srv))]
    TreeDisconnectResponse(tree_connect::TreeDisconnectResponse),

    // create
    #[br(pre_assert(matches!(command, Command::Create) && !from_srv))]
    CreateRequest(create::CreateRequest),
    #[br(pre_assert(matches!(command, Command::Create) && from_srv))]
    CreateResponse(create::CreateResponse),

    // close
    #[br(pre_assert(matches!(command, Command::Close) && !from_srv))]
    CloseRequest(create::CloseRequest),
    #[br(pre_assert(matches!(command, Command::Close) && from_srv))]
    CloseResponse(create::CloseResponse),

    // flush
    #[br(pre_assert(matches!(command, Command::Flush) && !from_srv))]
    FlushRequest(file::FlushRequest),
    #[br(pre_assert(matches!(command, Command::Flush) && from_srv))]
    FlushResponse(file::FlushResponse),

    // read
    #[br(pre_assert(matches!(command, Command::Read) && !from_srv))]
    ReadRequest(file::ReadRequest),
    #[br(pre_assert(matches!(command, Command::Read) && from_srv))]
    ReadResponse(file::ReadResponse),

    // write
    #[br(pre_assert(matches!(command, Command::Write) && !from_srv))]
    WriteRequest(file::WriteRequest),
    #[br(pre_assert(matches!(command, Command::Write) && from_srv))]
    WriteResponse(file::WriteResponse),

    // lock
    #[br(pre_assert(matches!(command, Command::Lock) && !from_srv))]
    LockRequest(lock::LockRequest),
    #[br(pre_assert(matches!(command, Command::Lock) && from_srv))]
    LockResponse(lock::LockResponse),

    // ioctl
    #[br(pre_assert(matches!(command, Command::Ioctl) && !from_srv))]
    IoctlRequest(ioctl::IoctlRequest),
    #[br(pre_assert(matches!(command, Command::Ioctl) && from_srv))]
    IoctlResponse(ioctl::IoctlResponse),

    // cancel
    #[br(pre_assert(matches!(command, Command::Cancel) && !from_srv))]
    CancelRequest(cancel::CancelRequest),

    // echo
    #[br(pre_assert(matches!(command, Command::Echo) && !from_srv))]
    EchoRequest(echo::EchoRequest),
    #[br(pre_assert(matches!(command, Command::Echo) && from_srv))]
    EchoResponse(echo::EchoResponse),

    // query directory
    #[br(pre_assert(matches!(command, Command::QueryDirectory) && !from_srv))]
    QueryDirectoryRequest(dir::QueryDirectoryRequest),
    #[br(pre_assert(matches!(command, Command::QueryDirectory) && from_srv))]
    QueryDirectoryResponse(dir::QueryDirectoryResponse),

    // change notify
    #[br(pre_assert(matches!(command, Command::ChangeNotify) && !from_srv))]
    ChangeNotifyRequest(notify::ChangeNotifyRequest),
    #[br(pre_assert(matches!(command, Command::ChangeNotify) && from_srv))]
    ChangeNotifyResponse(notify::ChangeNotifyResponse),

    // query info
    #[br(pre_assert(matches!(command, Command::QueryInfo) && !from_srv))]
    QueryInfoRequest(info::QueryInfoRequest),
    #[br(pre_assert(matches!(command, Command::QueryInfo) && from_srv))]
    QueryInfoResponse(info::QueryInfoResponse),

    // oplock
    #[br(pre_assert(matches!(command, Command::OplockBreak) && !from_srv))]
    OplockBreakAck(oplock::OplockBreakAck),
    #[br(pre_assert(matches!(command, Command::OplockBreak) && !from_srv))]
    LeaseBreakAck(oplock::LeaseBreakAck),
    #[br(pre_assert(matches!(command, Command::OplockBreak) && from_srv))]
    OplockBreakNotify(oplock::OplockBreakNotify),
    #[br(pre_assert(matches!(command, Command::OplockBreak) && from_srv))]
    LeaseBreakNotify(oplock::LeaseBreakNotify),
    #[br(pre_assert(matches!(command, Command::OplockBreak) && from_srv))]
    OplockBreakResponse(oplock::OplockBreakResponse),
    #[br(pre_assert(matches!(command, Command::OplockBreak) && from_srv))]
    LeaseBreakResponse(oplock::LeaseBreakResponse),

    // error response
    #[br(pre_assert(from_srv))]
    ErrorResponse(error::ErrorResponse),
}

impl Content {
    /// Get the command associated with this content.
    ///
    /// # Panics
    /// If the content is an error response, as it has no associated command.
    pub fn associated_cmd(&self) -> Command {
        use Content::*;
        match self {
            NegotiateRequest(_) | NegotiateResponse(_) => Command::Negotiate,
            SessionSetupRequest(_) | SessionSetupResponse(_) => Command::SessionSetup,
            LogoffRequest(_) | LogoffResponse(_) => Command::Logoff,
            TreeConnectRequest(_) | TreeConnectResponse(_) => Command::TreeConnect,
            TreeDisconnectRequest(_) | TreeDisconnectResponse(_) => Command::TreeDisconnect,
            CreateRequest(_) | CreateResponse(_) => Command::Create,
            CloseRequest(_) | CloseResponse(_) => Command::Close,
            FlushRequest(_) | FlushResponse(_) => Command::Flush,
            ReadRequest(_) | ReadResponse(_) => Command::Read,
            WriteRequest(_) | WriteResponse(_) => Command::Write,
            LockRequest(_) | LockResponse(_) => Command::Lock,
            IoctlRequest(_) | IoctlResponse(_) => Command::Ioctl,
            CancelRequest(_) => Command::Cancel,
            EchoRequest(_) | EchoResponse(_) => Command::Echo,
            QueryDirectoryRequest(_) | QueryDirectoryResponse(_) => Command::QueryDirectory,
            ChangeNotifyRequest(_) | ChangeNotifyResponse(_) => Command::ChangeNotify,
            QueryInfoRequest(_) | QueryInfoResponse(_) => Command::QueryInfo,
            // oplocks breaks/leases:
            OplockBreakAck(_)
            | LeaseBreakAck(_)
            | OplockBreakNotify(_)
            | OplockBreakResponse(_)
            | LeaseBreakNotify(_)
            | LeaseBreakResponse(_) => Command::OplockBreak,
            ErrorResponse(_) => panic!("Error has no matching command!"),
        }
    }
}

/// A plain, single, SMB2 message.
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct PlainMessage {
    pub header: Header,
    #[brw(args(&header.command, header.flags.server_to_redir()))]
    pub content: Content,
}

impl PlainMessage {
    pub fn new(content: Content) -> PlainMessage {
        PlainMessage {
            header: Header {
                credit_charge: 0,
                status: Status::Success,
                command: content.associated_cmd(),
                credit_request: 0,
                flags: HeaderFlags::new(),
                next_command: 0,
                message_id: u64::MAX,
                tree_id: 0,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }
}

/// Contains both tests and test helpers for other modules' tests requiring this module.
#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use super::*;

    /// Given a content, encode it into a Vec<u8> as if it were a full message,
    /// But return only the content bytes.
    ///
    /// This is useful when encoding structs with offsets relative to the beginning of the SMB header.
    pub fn encode_content(content: Content) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        let msg = PlainMessage::new(content);
        msg.write(&mut cursor).unwrap();
        let bytes_of_msg = cursor.into_inner();
        // We only want to return the content of the message, not the header. So cut the HEADER_SIZE bytes:
        bytes_of_msg[Header::STRUCT_SIZE..].to_vec()
    }

    pub fn decode_content(bytes: &[u8]) -> PlainMessage {
        let mut cursor = Cursor::new(bytes);
        cursor.read_le().unwrap()
    }
}
