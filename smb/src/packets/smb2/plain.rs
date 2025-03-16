use binrw::prelude::*;

use super::header::*;
use super::*;

/// Internal, one-use-macro to generate the request-response pairs for the `Content` enum.
/// In addition, it appends the special cases.
/// For example, the pair `(Negotiate, negotiate::Negotiate)` will generate:
/// ```ignore
/// #[br(pre_assert(matches!(command, Command::Negotiate) && !from_srv))]
/// NegotiateRequest(negotiate::NegotiateRequest),
/// #[br(pre_assert(matches!(command, Command::Negotiate) && from_srv))]
/// NegotiateResponse(negotiate::NegotiateResponse),
/// ...
/// ```
macro_rules! req_response_pair {
    (
        $({$cmd:ident, $struct_pfx:ident},)+
    ) => {
        paste::paste!{

#[derive(BinRead, BinWrite, Debug)]
#[brw(import(command: &Command, from_srv: bool))]
pub enum Content {
    $(
        #[br(pre_assert(matches!(command, Command::$cmd) && !from_srv))]
        [<$cmd Request>]($struct_pfx::[<$cmd Request>]),
        #[br(pre_assert(matches!(command, Command::$cmd) && from_srv))]
        [<$cmd Response>]($struct_pfx::[<$cmd Response>]),
    )*

    // cancel request
    #[br(pre_assert(matches!(command, Command::Cancel)))]
    CancelRequest(cancel::CancelRequest),

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
            $(
                [<$cmd Request>](_) => Command::$cmd,
                [<$cmd Response>](_) => Command::$cmd,
            )*

            CancelRequest(_) => Command::Cancel,
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
        }
    };
}

req_response_pair!(
    {Negotiate, negotiate},
    {SessionSetup, session_setup},
    {Logoff, session_setup},
    {TreeConnect, tree_connect},
    {TreeDisconnect, tree_connect},
    {Create, create},
    {Close, create},
    {Flush, file},
    {Read, file},
    {Write, file},
    {Lock, lock},
    {Ioctl, ioctl},
    {Echo, echo},
    {QueryDirectory, query_dir},
    {ChangeNotify, notify},
    {QueryInfo, info},
    {SetInfo, info},
);

impl Content {
    /// If this is a request has a payload, it returns the size of it.
    /// Otherwise, it returns 0.
    ///
    /// This method shall be used for calculating credits request & charge.
    pub fn req_payload_size(&self) -> u32 {
        use Content::*;
        match self {
            // 3.3.5.13
            WriteRequest(req) => req.buffer.len() as u32,
            // 3.3.5.15: InputCount + OutputCount
            IoctlRequest(req) => req.buffer.get_size() as u32 + req.max_output_response,
            _ => 0,
        }
    }

    /// If this is a request that expects a response with size,
    /// it returns that expected size.
    ///
    /// This method shall be used for calculating credits request & charge.
    pub fn expected_resp_size(&self) -> u32 {
        use Content::*;
        match self {
            // 3.3.5.12
            ReadRequest(req) => req.length,
            // 3.3.5.18
            QueryDirectoryRequest(req) => req.output_buffer_length,
            // 3.3.5.15: MaxInputCount + MaxOutputCount
            IoctlRequest(req) => req.max_input_response + req.max_output_response,
            _ => 0,
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
