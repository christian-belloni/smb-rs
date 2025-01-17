use binrw::prelude::*;

use super::header::*;
use super::*;

#[derive(BinRead, BinWrite, Debug)]
#[brw(import(command: &Command, from_srv: bool))]
pub enum Content {
    // negotiate
    #[br(pre_assert(command == &Command::Negotiate && !from_srv))]
    NegotiateRequest(negotiate::NegotiateRequest),
    #[br(pre_assert(command == &Command::Negotiate && from_srv))]
    NegotiateResponse(negotiate::NegotiateResponse),

    // session setup
    #[br(pre_assert(command == &Command::SessionSetup && !from_srv))]
    SessionSetupRequest(session_setup::SessionSetupRequest),
    #[br(pre_assert(command == &Command::SessionSetup && from_srv))]
    SessionSetupResponse(session_setup::SessionSetupResponse),

    // logoff
    #[br(pre_assert(command == &Command::Logoff && !from_srv))]
    LogoffRequest(session_setup::LogoffRequest),
    #[br(pre_assert(command == &Command::Logoff && from_srv))]
    LogoffResponse(session_setup::LogoffResponse),

    // tree connect
    #[br(pre_assert(command == &Command::TreeConnect && !from_srv))]
    TreeConnectRequest(tree_connect::TreeConnectRequest),
    #[br(pre_assert(command == &Command::TreeConnect && from_srv))]
    TreeConnectResponse(tree_connect::TreeConnectResponse),

    // tree disconnect
    #[br(pre_assert(command == &Command::TreeDisconnect && !from_srv))]
    TreeDisconnectRequest(tree_connect::TreeDisconnectRequest),
    #[br(pre_assert(command == &Command::TreeDisconnect && from_srv))]
    TreeDisconnectResponse(tree_connect::TreeDisconnectResponse),

    // create
    #[br(pre_assert(command == &Command::Create && !from_srv))]
    CreateRequest(create::CreateRequest),
    #[br(pre_assert(command == &Command::Create && from_srv))]
    CreateResponse(create::CreateResponse),

    // close
    #[br(pre_assert(command == &Command::Close && !from_srv))]
    CloseRequest(create::CloseRequest),
    #[br(pre_assert(command == &Command::Close && from_srv))]
    CloseResponse(create::CloseResponse),

    // flush
    #[br(pre_assert(command == &Command::Flush && !from_srv))]
    FlushRequest(file::FlushRequest),
    #[br(pre_assert(command == &Command::Flush && from_srv))]
    FlushResponse(file::FlushResponse),

    // read
    #[br(pre_assert(command == &Command::Read && !from_srv))]
    ReadRequest(file::ReadRequest),
    #[br(pre_assert(command == &Command::Read && from_srv))]
    ReadResponse(file::ReadResponse),

    // write
    #[br(pre_assert(command == &Command::Write && !from_srv))]
    WriteRequest(file::WriteRequest),
    #[br(pre_assert(command == &Command::Write && from_srv))]
    WriteResponse(file::WriteResponse),

    // query directory
    #[br(pre_assert(command == &Command::QueryDirectory && !from_srv))]
    QueryDirectoryRequest(dir::QueryDirectoryRequest),
    #[br(pre_assert(command == &Command::QueryDirectory && from_srv))]
    QueryDirectoryResponse(dir::QueryDirectoryResponse),

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
            QueryDirectoryRequest(_) | QueryDirectoryResponse(_) => Command::QueryDirectory,
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
