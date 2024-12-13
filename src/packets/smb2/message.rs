use binrw::prelude::*;
use super::header::*;
use super::negotiate;

#[derive(BinRead, BinWrite, Debug)]
#[br(import(smb_command: &SMBCommand))]
enum SMBMessageContent {
    #[br(pre_assert(smb_command == &SMBCommand::Negotiate))]
    SMBNegotiateRequest(negotiate::SMBNegotiateRequest),
}

#[derive(BinRead, BinWrite, Debug)]
#[brw(big)]
pub struct SMB2Message {
    header: SMB2MessageHeader,
    #[br(args(&header.command))]
    content: SMBMessageContent
}


impl SMB2Message {
    pub fn build() -> SMB2Message {
        SMB2Message {
            header: SMB2MessageHeader {
                credit_charge: 0,
                status: 0,
                command: SMBCommand::Negotiate,
                credit_request: 0,
                flags: 0,
                next_command: 0,
                message_id: 1,
                reserved: 0x0000feff,
                tree_id: 0,
                session_id: 0,
                signature: 0
            },
            content: SMBMessageContent::SMBNegotiateRequest(negotiate::SMBNegotiateRequest::build())
        }
    }
}
