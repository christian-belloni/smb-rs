use binrw::prelude::*;
use crate::pos_marker::PosMarker;

use super::header::*;
use super::negotiate;

#[derive(BinRead, BinWrite, Debug)]
#[brw(import(smb_command: &SMB2Command, flags_server_to_redir: bool, header_start: u64))]
pub enum SMBMessageContent {
    #[br(pre_assert(smb_command == &SMB2Command::Negotiate && !flags_server_to_redir))]
    SMBNegotiateRequest(negotiate::SMBNegotiateRequest),
    #[br(pre_assert(smb_command == &SMB2Command::Negotiate && flags_server_to_redir))]
    SMBNegotiateResponse(negotiate::SMBNegotiateResponse)
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(big)]
pub struct SMB2Message {
    #[brw(calc = PosMarker::default())]
    pub header_start: PosMarker<()>,
    pub header: SMB2MessageHeader,
    #[brw(args(&header.command, header.flags.server_to_redir(), header_start.pos.get()))]
    pub content: SMBMessageContent
}


impl SMB2Message {
    pub fn new(content: SMBMessageContent) -> SMB2Message {
        SMB2Message {
            header: SMB2MessageHeader {
                credit_charge: 0,
                status: 0,
                command: SMB2Command::Negotiate,
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
