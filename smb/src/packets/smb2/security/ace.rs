//! MS-DTYP 2.4.4: ACE

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::{binrw_util::prelude::*, smb2::FileAccessMask};

use super::SID;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ACE {
    #[bw(calc = value.get_type())]
    pub ace_type: AceType,
    pub ace_flags: AceFlags,
    #[bw(calc = PosMarker::default())]
    _ace_size: PosMarker<u16>,
    #[br(args(ace_type))]
    #[bw(write_with = PosMarker::write_size, args(&_ace_size))]
    pub value: AceValue,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(ace_type: AceType))]
pub enum AceValue {
    #[br(pre_assert(matches!(ace_type, AceType::AccessAllowed)))]
    AccessAllowed(AccessAllowedAce),
}

impl AceValue {
    pub fn get_type(&self) -> AceType {
        match self {
            AceValue::AccessAllowed(_) => AceType::AccessAllowed,
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AccessAllowedAce {
    pub access_mask: FileAccessMask,
    pub sid: SID,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum AceType {
    AccessAllowed = 0,
    AccessDenied = 1,
    SystemAudit = 2,
    SystemAlarm = 3,
    AccessAllowedCompound = 4,
    AccessAllowedObject = 5,
    AccessDeniedObject = 6,
    SystemAuditObject = 7,
    SystemAlarmObject = 8,
    AccessAllowedCallback = 9,
    AccessDeniedCallback = 10,
    AccessAllowedCallbackObject = 11,
    AccessDeniedCallbackObject = 12,
    SystemAuditCallback = 13,
    SystemAlarmCallback = 14,
    SystemAuditCallbackObject = 15,
    SystemAlarmCallbackObject = 16,
    SystemMandatoryLabel = 17,
    SystemResourceAttribute = 18,
    SystemScopedPolicyId = 19,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct AceFlags {
    pub object_inherit: bool,
    pub container_inherit: bool,
    pub no_propagate_inherit: bool,
    pub inherit_only: bool,

    pub inherited: bool,
    #[skip]
    __: bool,
    pub successful_access: bool,
    pub failed_access: bool,
}
