use binrw::prelude::*;

use super::header::*;
use super::*;

#[derive(BinRead, BinWrite, Debug)]
#[brw(import(smb_command: &SMB2Command, flags_server_to_redir: bool))]
pub enum SMBMessageContent {
    // negotiate
    #[br(pre_assert(smb_command == &SMB2Command::Negotiate && !flags_server_to_redir))]
    SMBNegotiateRequest(negotiate::SMBNegotiateRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Negotiate && flags_server_to_redir))]
    SMBNegotiateResponse(negotiate::SMBNegotiateResponse),

    // session setup
    #[br(pre_assert(smb_command == &SMB2Command::SessionSetup && !flags_server_to_redir))]
    SMBSessionSetupRequest(session_setup::SMB2SessionSetupRequest),
    #[br(pre_assert(smb_command == &SMB2Command::SessionSetup && flags_server_to_redir))]
    SMBSessionSetupResponse(session_setup::SMB2SessionSetupResponse),

    // logoff
    #[br(pre_assert(smb_command == &SMB2Command::Logoff && !flags_server_to_redir))]
    SMBLogoffRequest(session_setup::SMB2LogoffRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Logoff && flags_server_to_redir))]
    SMBLogoffResponse(session_setup::SMB2LogoffResponse),

    // tree connect
    #[br(pre_assert(smb_command == &SMB2Command::TreeConnect && !flags_server_to_redir))]
    SMBTreeConnectRequest(tree_connect::SMB2TreeConnectRequest),
    #[br(pre_assert(smb_command == &SMB2Command::TreeConnect && flags_server_to_redir))]
    SMBTreeConnectResponse(tree_connect::SMB2TreeConnectResponse),

    // tree disconnect
    #[br(pre_assert(smb_command == &SMB2Command::TreeDisconnect && !flags_server_to_redir))]
    SMBTreeDisconnectRequest(tree_connect::SMB2TreeDisconnectRequest),
    #[br(pre_assert(smb_command == &SMB2Command::TreeDisconnect && flags_server_to_redir))]
    SMBTreeDisconnectResponse(tree_connect::SMB2TreeDisconnectResponse),

    // create
    #[br(pre_assert(smb_command == &SMB2Command::Create && !flags_server_to_redir))]
    SMBCreateRequest(create::SMB2CreateRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Create && flags_server_to_redir))]
    SMBCreateResponse(create::SMB2CreateResponse),

    // close
    #[br(pre_assert(smb_command == &SMB2Command::Close && !flags_server_to_redir))]
    SMBCloseRequest(create::SMB2CloseRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Close && flags_server_to_redir))]
    SMBCloseResponse(create::SMB2CloseResponse),

    // flush
    #[br(pre_assert(smb_command == &SMB2Command::Flush && !flags_server_to_redir))]
    SMBFlushRequest(file::SMB2FlushRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Flush && flags_server_to_redir))]
    SMBFlushResponse(file::SMB2FlushResponse),

    // read
    #[br(pre_assert(smb_command == &SMB2Command::Read && !flags_server_to_redir))]
    SMBReadRequest(file::SMB2ReadRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Read && flags_server_to_redir))]
    SMBReadResponse(file::SMB2ReadResponse),

    // write
    #[br(pre_assert(smb_command == &SMB2Command::Write && !flags_server_to_redir))]
    SMBWriteRequest(file::SMB2WriteRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Write && flags_server_to_redir))]
    SMBWriteResponse(file::SMB2WriteResponse),

    // query directory
    #[br(pre_assert(smb_command == &SMB2Command::QueryDirectory && !flags_server_to_redir))]
    SMBQueryDirectoryRequest(dir::SMB2QueryDirectoryRequest),
    #[br(pre_assert(smb_command == &SMB2Command::QueryDirectory && flags_server_to_redir))]
    SMBQueryDirectoryResponse(dir::SMB2QueryDirectoryResponse),

    // error response
    #[br(pre_assert(flags_server_to_redir))]
    ErrorResponse(error::ErrorResponse),
}

impl SMBMessageContent {
    pub fn associated_cmd(&self) -> SMB2Command {
        use SMBMessageContent::*;
        match self {
            SMBNegotiateRequest(_) | SMBNegotiateResponse(_) => SMB2Command::Negotiate,
            SMBSessionSetupRequest(_) | SMBSessionSetupResponse(_) => SMB2Command::SessionSetup,
            SMBLogoffRequest(_) | SMBLogoffResponse(_) => SMB2Command::Logoff,
            SMBTreeConnectRequest(_) | SMBTreeConnectResponse(_) => SMB2Command::TreeConnect,
            SMBTreeDisconnectRequest(_) | SMBTreeDisconnectResponse(_) => {
                SMB2Command::TreeDisconnect
            }
            SMBCreateRequest(_) | SMBCreateResponse(_) => SMB2Command::Create,
            SMBCloseRequest(_) | SMBCloseResponse(_) => SMB2Command::Close,
            SMBFlushRequest(_) | SMBFlushResponse(_) => SMB2Command::Flush,
            SMBReadRequest(_) | SMBReadResponse(_) => SMB2Command::Read,
            SMBWriteRequest(_) | SMBWriteResponse(_) => SMB2Command::Write,
            SMBQueryDirectoryRequest(_) | SMBQueryDirectoryResponse(_) => {
                SMB2Command::QueryDirectory
            },
            ErrorResponse(_) => panic!("Error has no matching command!"),
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct SMB2Message {
    pub header: SMB2MessageHeader,
    #[brw(args(&header.command, header.flags.server_to_redir()))]
    pub content: SMBMessageContent,
}

impl SMB2Message {
    pub fn new(content: SMBMessageContent) -> SMB2Message {
        SMB2Message {
            header: SMB2MessageHeader {
                credit_charge: 0,
                status: SMB2Status::Success,
                command: content.associated_cmd(),
                credit_request: 0,
                flags: SMB2HeaderFlags::new(),
                next_command: 0,
                message_id: u64::MAX,
                reserved: 0x0000feff,
                tree_id: 0,
                session_id: 0,
                signature: 0,
            },
            content,
        }
    }
}
