use binrw::prelude::*;
use super::header::*;
use super::negotiate;

#[derive(BinRead, BinWrite, Debug)]
#[br(import(smb_command: &SMBCommand, flags_server_to_redir: bool))]
pub enum SMBMessageContent {
    #[br(pre_assert(smb_command == &SMBCommand::Negotiate && !flags_server_to_redir))]
    SMBNegotiateRequest(negotiate::SMBNegotiateRequest),
    #[br(pre_assert(smb_command == &SMBCommand::Negotiate && flags_server_to_redir))]
    SMBNegotiateResponse(negotiate::SMBNegotiateResponse)
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
pub struct SMB2Message {
    header: SMB2MessageHeader,
    #[br(args(&header.command, header.flags.server_to_redir()))]
    content: SMBMessageContent
}


impl SMB2Message {
    pub fn build(content: SMBMessageContent) -> SMB2Message {
        SMB2Message {
            header: SMB2MessageHeader {
                credit_charge: 0,
                status: 0,
                command: SMBCommand::Negotiate,
                credit_request: 0,
                flags: SMB2HeaderFlags::new(),
                next_command: 0,
                message_id: 1,
                reserved: 0x0000feff,
                tree_id: 0,
                session_id: 0,
                signature: 0
            },
            content
        }
    }
}
