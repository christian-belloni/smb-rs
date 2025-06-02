use binrw::prelude::*;
use modular_bitfield::prelude::*;

use super::guid::Guid;

macro_rules! rpc_pkts {
    ($
        ($name:ident {
            $($pdu_type:ident = $pdu_oper_id:literal,)+
        }),+
    ) => {
        paste::paste! {
                    $(
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct [<DcRpcCo $name Pkt>] {
    pub header: [<DcRpcCoPkt $name Header>],
    #[br(args(header.ptype))]
    pub content: [<DcRpcCoPkt $name Content>],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum [<DceRpcCoPkt $name Type>] {
    $(
        $pdu_type = $pdu_oper_id,
    )+
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct [<DcRpcCoPkt $name Header>] {
    #[bw(calc = 5)]
    #[br(assert(rpc_vers_major == 5))]
    rpc_vers_major: u8,
    #[bw(calc = 0)]
    #[br(assert(rpc_vers_minor == 0))]
    rpc_vers_minor: u8,
    pub ptype: [<DceRpcCoPkt $name Type>],
    pub pfc_flags: DceRpcCoPktFlags,
    pub packed_drep: u32,
    pub frag_length: u16,
    #[br(assert(auth_length == 0))]
    #[bw(calc = 0)]
    auth_length: u16, // auth currently unsupported.
    pub call_id: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(ptype: [<DceRpcCoPkt $name Type>]))]
pub enum [<DcRpcCoPkt $name Content>] {
        $(
            #[br(pre_assert(ptype == [<DceRpcCoPkt $name Type>]::$pdu_type))]
            $pdu_type([<DcRpcCoPkt $pdu_type>]),
        )+
}

impl [<DcRpcCoPkt $name Content>] {
    pub fn get_type(&self) -> [<DceRpcCoPkt $name Type>] {
        match self {
            $(
                Self::$pdu_type(_) => [<DceRpcCoPkt $name Type>]::$pdu_type,
            )+
        }
    }
}
                    )+
                }
    };
}

rpc_pkts! {
    Request {
        // Request = 0,
        Bind = 11,
        // AlterContext = 14,
        // Cancel = 18,
        // Orphaned = 19,
    },
    Response {
        // Response = 2,
        // Fault = 3,
        BindAck = 12,
        // BindNak = 13,
        // AlterContextResp = 15,
        // Shutdown = 17,
    }
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct DceRpcCoPktFlags {
    first_frag: bool,
    last_frag: bool,
    /// Cancel was pending at sender
    pending_cancel: bool,
    #[skip]
    __: bool, // reserved
    /// supports concurrent multiplexing of a single connection.
    conc_mpx: bool,
    /// only meaningful on `fault' packet;
    /// if true, guaranteed call did not execute.
    did_not_execute: bool,
    /// `maybe' call semantics requested
    maybe: bool,
    /// if true, a non-nil object UUID was specified in the handle,
    /// and is present in the optional object field.
    /// If false, the object field is omitted.
    object_uuid: bool,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBind {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,

    num_context_items: u8,
    #[br(count = num_context_items)]
    pub context_elements: Vec<DcRpcCoPktBindContextElement>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBindContextElement {
    pub context_id: u16,
    pub num_transfer_syntaxes: u8,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u8,
    pub abstract_syntax: DceRpcSyntaxId,
    #[br(count = num_transfer_syntaxes)]
    pub transfer_syntaxes: Vec<DceRpcSyntaxId>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DceRpcSyntaxId {
    pub uuid: Guid,
    pub version: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBindAck {
    #[br(align_before = 4)]
    num_results: u8,
    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    _reserved2: u16,

    #[br(count = num_results)]
    results: Vec<DcRpcCoPktBindAckResult>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBindAckResult {
    pub result: DceRpcCoPktBindAckDefResult,
    pub reason: DcRpcCoPktBindAckReason,
    pub syntax: DceRpcSyntaxId,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u16))]
pub enum DceRpcCoPktBindAckDefResult {
    Acceptance = 0,
    UserRejection = 1,
    ProviderRejection = 2,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u16))]
pub enum DcRpcCoPktBindAckReason {
    NotSpecified = 0,
    AbstractSyntaxNotSupported = 1,
    ProposedTransferSyntaxesNotSupported = 2,
    LocalLimitExceeded = 3,
}

// #[cfg(test)]
// mod tests {
//     pub fn
// }
