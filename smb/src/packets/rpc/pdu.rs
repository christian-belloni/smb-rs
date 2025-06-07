//! DCE/RPC PDUs for connection-oriented RPC over SMB.

use crate::packets::binrw_util::prelude::*;
use crate::packets::guid::Guid;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

pub const DCE_RPC_VERSION: DceRpcVersion = DceRpcVersion { major: 5, minor: 0 };

macro_rules! rpc_pkts {
    ($
        ($name:ident {
            $($pdu_type:ident = $pdu_oper_id:literal,)+
        }),+
    ) => {
        paste::paste! {
                    $(
// Entire Packet, for each direction (Request/Response).
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct [<DceRpcCo $name Pkt>] {
    #[bw(calc = PosMarker::default())]
    _save_pdu_start: PosMarker<()>,
    #[br(assert(rpc_ver == DCE_RPC_VERSION))]
    #[bw(calc = DCE_RPC_VERSION)]
    rpc_ver: DceRpcVersion,
    #[bw(calc = content.get_type())]
    ptype: [<DceRpcCoPkt $name Type>],
    pfc_flags: DceRpcCoPktFlags,
    pub packed_drep: u32,
    #[bw(calc = PosMarker::default())]
    _frag_length: PosMarker<u16>,
    #[br(assert(auth_length == 0))]
    #[bw(calc = 0)]
    auth_length: u16, // auth currently disabled.
    call_id: u32,
    #[br(args(ptype), map_stream = |s| s.take_seek(_frag_length.value as u64))]
    content: [<DcRpcCoPkt $name Content>],

    #[bw(write_with = PosMarker::write_roff_b, args(&_frag_length, &_save_pdu_start))]
    _write_pdu_size: ()
}

impl [<DceRpcCo $name Pkt>] {
    pub const COMMON_SIZE_BYTES: usize = 16;

    pub fn new(content: [<DcRpcCoPkt $name Content>], call_id: u32, flags: DceRpcCoPktFlags, packed_drep: u32) -> Self {
        Self {
            pfc_flags: flags,
            packed_drep, // little-endian, ASCII
            call_id, // TODO: make this configurable?
            content,
            _write_pdu_size: (),
        }
    }

    pub fn content(&self) -> &[<DcRpcCoPkt $name Content>] {
        &self.content
    }

    pub fn call_id(&self) -> u32 {
        self.call_id
    }

    pub fn pfc_flags(&self) -> DceRpcCoPktFlags {
        self.pfc_flags
    }

    pub fn packed_drep(&self) -> u32 {
        self.packed_drep
    }
}

impl TryFrom<&[u8]> for [<DceRpcCo $name Pkt>] {
    type Error = binrw::Error;
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(data);
        Self::read_le(&mut cursor)
    }
}

impl TryInto<Vec<u8>> for [<DceRpcCo $name Pkt>] {
    type Error = binrw::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        self.write_le(&mut cursor)?;
        Ok(cursor.into_inner())
    }
}

// Packet Type (Bind/BindAck, etc.)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum [<DceRpcCoPkt $name Type>] {
    $(
        $pdu_type = $pdu_oper_id,
    )+
}

// Packet Content, redefined for each direction to
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
    /// Retruns the Type of the packet by it's content.
    pub fn get_type(&self) -> [<DceRpcCoPkt $name Type>] {
        match self {
            $(
                Self::$pdu_type(_) => [<DceRpcCoPkt $name Type>]::$pdu_type,
            )+
        }
    }
}

$(
    impl Into<[<DcRpcCoPkt $name Content>]> for [<DcRpcCoPkt $pdu_type>] {
        fn into(self) -> [<DcRpcCoPkt $name Content>] {
            [<DcRpcCoPkt $name Content>]::$pdu_type(self)
        }
    }
)+
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
        BindNak = 13,
        // AlterContextResp = 15,
        // Shutdown = 17,
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DceRpcVersion {
    pub major: u8,
    pub minor: u8,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct DceRpcCoPktFlags {
    pub first_frag: bool,
    pub last_frag: bool,
    /// Cancel was pending at sender
    pub pending_cancel: bool,
    #[skip]
    __: bool, // reserved
    /// supports concurrent multiplexing of a single connection.
    pub conc_mpx: bool,
    /// only meaningful on `fault' packet;
    /// if true, guaranteed call did not execute.
    pub did_not_execute: bool,
    #[skip]
    __: bool, // implementations may ignore the `maybe` flag (MS-RPCE)
    /// if true, a non-nil object UUID was specified in the handle,
    /// and is present in the optional object field.
    /// If false, the object field is omitted.
    pub object_uuid: bool,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBind {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,

    #[bw(calc = context_elements.len() as u8)]
    num_context_items: u8,

    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    _reserved2: u16,

    #[br(count = num_context_items)]
    pub context_elements: Vec<DcRpcCoPktBindContextElement>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBindContextElement {
    pub context_id: u16,
    #[bw(calc = transfer_syntaxes.len() as u8)]
    pub num_transfer_syntaxes: u8,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u8,
    pub abstract_syntax: DceRpcSyntaxId,
    #[br(count = num_transfer_syntaxes)]
    pub transfer_syntaxes: Vec<DceRpcSyntaxId>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DceRpcSyntaxId {
    pub uuid: Guid,
    pub version: u32,
}

impl DceRpcSyntaxId {
    pub const ZERO: Self = Self {
        uuid: Guid::ZERO,
        version: 0,
    };
}

impl std::fmt::Display for DceRpcSyntaxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}/{})", self.uuid, self.version)
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBindAck {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,

    #[bw(calc = port_spec.size() as u16)]
    port_spec_len: u16,
    #[br(args(port_spec_len as u64))]
    pub port_spec: SizedAnsiString,

    #[br(align_before = 4)]
    #[bw(calc = results.len() as u8)]
    num_results: u8,
    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    _reserved2: u16,

    #[br(count = num_results)]
    pub results: Vec<DcRpcCoPktBindAckResult>,
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
    NegotiateAck = 3,
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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DcRpcCoPktBindNak {
    pub reason: DceRpcCoPktBindRejectReason,
    #[bw(calc = protocols.len() as u8)]
    num_protocols: u8,
    #[br(count = num_protocols)]
    pub protocols: Vec<DceRpcVersion>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u16))]
pub enum DceRpcCoPktBindRejectReason {
    ReasonNotSpecified = 0,
    TemporaryCongestion = 1,
    LocalLimitExceeded = 2,
    CalledPaddrUnknown = 3,
    ProtocolVersionNotSupported = 4,
    DefaultContextNotSupported = 5,
    UserDataNotReadable = 6,
    NoPsapAvailable = 7,
    AuthenticationTypeNotRecognized = 8,
    AuthenticationTypeNotSupported = 9,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_bind_writes() {
        let wkksvc_abstract_syntax = DceRpcSyntaxId {
            uuid: Guid::from_str("6bffd098-a112-3610-9833-46c3f87e345a").unwrap(),
            version: 1,
        };

        let bind_request = DceRpcCoRequestPkt::new(
            DcRpcCoPktBind {
                max_xmit_frag: 4280,
                max_recv_frag: 4280,
                assoc_group_id: 0,
                context_elements: vec![
                    DcRpcCoPktBindContextElement {
                        context_id: 0,
                        abstract_syntax: wkksvc_abstract_syntax.clone(),
                        transfer_syntaxes: vec![DceRpcSyntaxId {
                            uuid: Guid::from_str("8a885d04-1ceb-11c9-9fe8-08002b104860").unwrap(),
                            version: 2,
                        }],
                    },
                    DcRpcCoPktBindContextElement {
                        context_id: 1,
                        abstract_syntax: wkksvc_abstract_syntax.clone(),
                        transfer_syntaxes: vec![DceRpcSyntaxId {
                            uuid: Guid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
                            version: 1,
                        }],
                    },
                    DcRpcCoPktBindContextElement {
                        context_id: 2,
                        abstract_syntax: wkksvc_abstract_syntax.clone(),
                        transfer_syntaxes: vec![DceRpcSyntaxId {
                            uuid: Guid::from_str("6cb71c2c-9812-4540-0300-000000000000").unwrap(),
                            version: 1,
                        }],
                    },
                ],
            }
            .into(),
            2,
            DceRpcCoPktFlags::new()
                .with_first_frag(true)
                .with_last_frag(true),
            0x00000010,
        );

        let mut cursor = std::io::Cursor::new(Vec::new());
        bind_request.write_le(&mut cursor).unwrap();
        assert_eq!(
            cursor.into_inner(),
            [
                0x5, 0x0, 0xb, 0x3, 0x10, 0x0, 0x0, 0x0, 0xa0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0,
                0xb8, 0x10, 0xb8, 0x10, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0,
                0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36, 0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e,
                0x34, 0x5a, 0x1, 0x0, 0x0, 0x0, 0x4, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
                0x9f, 0xe8, 0x8, 0x0, 0x2b, 0x10, 0x48, 0x60, 0x2, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1,
                0x0, 0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36, 0x98, 0x33, 0x46, 0xc3, 0xf8,
                0x7e, 0x34, 0x5a, 0x1, 0x0, 0x0, 0x0, 0x33, 0x5, 0x71, 0x71, 0xba, 0xbe, 0x37,
                0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0,
                0x1, 0x0, 0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36, 0x98, 0x33, 0x46, 0xc3,
                0xf8, 0x7e, 0x34, 0x5a, 0x1, 0x0, 0x0, 0x0, 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98,
                0x40, 0x45, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0
            ]
        )
    }

    #[test]
    fn test_bind_ack_parses() {
        let data = [
            0x5, 0x0, 0xc, 0x3, 0x10, 0x0, 0x0, 0x0, 0x74, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0xb8,
            0x10, 0xb8, 0x10, 0x29, 0x3b, 0x0, 0x0, 0xd, 0x0, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c,
            0x77, 0x6b, 0x73, 0x73, 0x76, 0x63, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x33, 0x5, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83,
            0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36, 0x1, 0x0, 0x0, 0x0, 0x3, 0x0, 0x3, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0,
        ];
        let mut cursor = std::io::Cursor::new(data);
        let bind_ack: DceRpcCoResponsePkt = DceRpcCoResponsePkt::read_le(&mut cursor).unwrap();
        assert_eq!(
            bind_ack,
            DceRpcCoResponsePkt::new(
                DcRpcCoPktBindAck {
                    max_xmit_frag: 4280,
                    max_recv_frag: 4280,
                    assoc_group_id: 0x3b29,
                    port_spec: "\\PIPE\\wkssvc\0".into(),
                    results: vec![
                        DcRpcCoPktBindAckResult {
                            result: DceRpcCoPktBindAckDefResult::ProviderRejection,
                            reason: DcRpcCoPktBindAckReason::ProposedTransferSyntaxesNotSupported,
                            syntax: DceRpcSyntaxId::ZERO
                        },
                        DcRpcCoPktBindAckResult {
                            result: DceRpcCoPktBindAckDefResult::Acceptance,
                            reason: DcRpcCoPktBindAckReason::NotSpecified,
                            syntax: DceRpcSyntaxId {
                                uuid: Guid::from_str("71710533-beba-4937-8319-b5dbef9ccc36")
                                    .unwrap(),
                                version: 1,
                            }
                        },
                        DcRpcCoPktBindAckResult {
                            result: DceRpcCoPktBindAckDefResult::NegotiateAck,
                            reason: DcRpcCoPktBindAckReason::LocalLimitExceeded,
                            syntax: DceRpcSyntaxId::ZERO
                        }
                    ]
                }
                .into(),
                2,
                DceRpcCoPktFlags::new()
                    .with_first_frag(true)
                    .with_last_frag(true),
                0x00000010,
            )
        )
    }

    #[test]
    fn test_bind_nak_parses() {
        let data = [
            0x5, 0x0, 0xd, 0x3, 0x10, 0x0, 0x0, 0x0, 0x18, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0,
        ];
        let mut cursor = std::io::Cursor::new(data);
        let bind_nak: DceRpcCoResponsePkt = DceRpcCoResponsePkt::read_le(&mut cursor).unwrap();
        assert_eq!(
            bind_nak,
            DceRpcCoResponsePkt::new(
                DcRpcCoPktBindNak {
                    reason: DceRpcCoPktBindRejectReason::ReasonNotSpecified,
                    protocols: vec![DceRpcVersion { major: 5, minor: 0 }],
                }
                .into(),
                2,
                DceRpcCoPktFlags::new()
                    .with_first_frag(true)
                    .with_last_frag(true),
                0x00000010,
            )
        );
    }
}
