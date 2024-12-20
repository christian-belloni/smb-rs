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
    SMBSessionSetupRequest(session::SMB2SessionSetupRequest),
    #[br(pre_assert(smb_command == &SMB2Command::SessionSetup && flags_server_to_redir))]
    SMBSessionSetupResponse(session::SMB2SessionSetupResponse),

    // logoff
    #[br(pre_assert(smb_command == &SMB2Command::Logoff && !flags_server_to_redir))]
    SMBLogoffRequest(session::SMB2LogoffRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Logoff && flags_server_to_redir))]
    SMBLogoffResponse(session::SMB2LogoffResponse),

    // tree connect
    #[br(pre_assert(smb_command == &SMB2Command::TreeConnect && !flags_server_to_redir))]
    SMBTreeConnectRequest(tree::SMB2TreeConnectRequest),
    #[br(pre_assert(smb_command == &SMB2Command::TreeConnect && flags_server_to_redir))]
    SMBTreeConnectResponse(tree::SMB2TreeConnectResponse),
}

impl SMBMessageContent {
    pub fn associated_cmd(&self) -> SMB2Command {
        use SMBMessageContent::*;
        match self {
            SMBNegotiateRequest(_) | SMBNegotiateResponse(_) => SMB2Command::Negotiate,
            SMBSessionSetupRequest(_) | SMBSessionSetupResponse(_)  => SMB2Command::SessionSetup,
            SMBLogoffRequest(_) | SMBLogoffResponse(_) => SMB2Command::Logoff,
            SMBTreeConnectRequest(_) | SMBTreeConnectResponse(_) => SMB2Command::TreeConnect,
        }
    }
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct SMB2Message {
    pub header: SMB2MessageHeader,
    #[brw(args(&header.command, header.flags.server_to_redir()))]
    pub content: SMBMessageContent
}


impl SMB2Message {
    pub fn new(content: SMBMessageContent, msg_id: u64, credits_charge: u16, credits_req: u16, flags: SMB2HeaderFlags, session_id: u64) -> SMB2Message {
        SMB2Message {
            header: SMB2MessageHeader {
                credit_charge: credits_charge,
                status: 0,
                command: content.associated_cmd(),
                credit_request: credits_req,
                flags: flags,
                next_command: 0,
                message_id: msg_id,
                reserved: 0x0000feff,
                tree_id: 0,
                session_id,
                signature: 0
            },
            content
        }
    }
}
