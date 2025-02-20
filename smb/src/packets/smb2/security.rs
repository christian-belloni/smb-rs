//! MS-DTYP 2.4.6: Security Descriptor

use std::str::FromStr;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::packets::binrw_util::prelude::*;

use super::FileAccessMask;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SecurityDescriptor {
    #[bw(calc = 1)]
    #[br(assert(_revision == 1))]
    _revision: u8,
    pub sbz1: u8,
    #[brw(assert(control.self_relative()))]
    pub control: SecurityDescriptorControl,
    #[bw(calc = PosMarker::default())]
    offset_owner: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    offset_group: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    offset_sacl: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    offset_dacl: PosMarker<u32>,
    #[br(if(offset_owner.value != 0))]
    pub owner_sid: Option<SID>,
    #[br(if(offset_group.value != 0))]
    pub group_sid: Option<SID>,
    #[bw(assert(sacl.is_some() == control.sacl_present()))]
    #[br(assert((offset_sacl.value != 0) == (control.sacl_present())))]
    #[br(if(offset_sacl.value != 0))]
    pub sacl: Option<ACL>,
    #[bw(assert(dacl.is_some() == control.dacl_present()))]
    #[br(assert((offset_dacl.value != 0) == control.dacl_present()))]
    #[br(if(offset_dacl.value != 0))]
    pub dacl: Option<ACL>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct SecurityDescriptorControl {
    pub owner_defaulted: bool,
    pub group_defaulted: bool,
    pub dacl_present: bool,
    pub dacl_defaulted: bool,

    pub sacl_present: bool,
    pub sacl_defaulted: bool,
    pub dacl_trusted: bool,
    pub server_security: bool,

    pub dacl_computed: bool,
    pub sacl_computed: bool,
    pub dacl_auto_inherited: bool,
    pub sacl_auto_inherited: bool,

    pub dacl_protected: bool,
    pub sacl_protected: bool,
    pub rm_control_valid: bool,
    pub self_relative: bool,
}

/// MS-DTYP 2.4.2.2
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SID {
    #[bw(calc = 1)]
    #[br(assert(revision == 1))]
    revision: u8,
    #[bw(try_calc = sub_authority.len().try_into())]
    sub_authority_count: u8,
    #[brw(big)] // WE LOVE MICROSOFT!
    #[br(parse_with = read_u48)]
    #[bw(write_with = write_u48)]
    pub identifier_authority: u64,
    #[br(count = sub_authority_count)]
    pub sub_authority: Vec<u32>,
}
impl SID {
    const PREFIX: &str = "S-1-";

    pub const S_ADMINISTRATORS: &str = "S-1-5-32-544";
    pub const S_LOCAL_SYSTEM: &str = "S-1-5-18";
    pub const S_EVERYONE: &str = "S-1-1-0";
}

impl FromStr for SID {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 1. starts with S-1-:
        if !s.starts_with(Self::PREFIX) {
            return Err(());
        }
        let mut s = s[Self::PREFIX.len()..].split('-');
        // 2. authority is a number, possibly in hex.
        let identifier_authority = match s.next() {
            Some("0x") => {
                // hex is only for sub-authorities > 32 bits!
                let p = u64::from_str_radix(s.next().ok_or(())?, 16).map_err(|_| ())?;
                if p >> 32 == 0 {
                    p
                } else {
                    return Err(());
                }
            }
            Some(x) => x.parse().map_err(|_| ())?,
            None => return Err(()),
        };
        // 3. sub-authorities are numbers.
        let sub_authority = s
            .map(|x| x.parse().map_err(|_| ()))
            .collect::<Result<_, _>>()?;
        Ok(SID {
            identifier_authority,
            sub_authority,
        })
    }
}

impl std::fmt::Display for SID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // MS-DTYP 2.4.2.1: SID String Format
        write!(f, "S-1-")?;
        if self.identifier_authority >> 32 == 0 {
            write!(f, "{}", self.identifier_authority)?;
        } else {
            write!(f, "0x{:x}", self.identifier_authority)?;
        }
        for sub_authority in &self.sub_authority {
            write!(f, "-{}", sub_authority)?;
        }
        Ok(())
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ACL {
    acl_revision: AclRevision,
    #[bw(calc = 0)]
    #[br(assert(sbz1 == 0))]
    sbz1: u8,
    #[bw(calc = PosMarker::default())]
    _acl_size: PosMarker<u16>,
    #[bw(calc = ace.len() as u16)]
    ace_count: u16,
    #[bw(calc = 0)]
    #[br(assert(sbz2 == 0))]
    sbz2: u16,
    #[br(count = ace_count)]
    #[bw(write_with = PosMarker::write_size, args(&_acl_size))]
    ace: Vec<ACE>,
}

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
    access_mask: FileAccessMask,
    sid: SID,
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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum AclRevision {
    /// Windows NT 4.0
    Nt4 = 2,
    /// Active directory
    DS = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_owner_group_parse() {
        let buff = &[
            0x1, 0x0, 0x0, 0x80, 0x14, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d,
            0xa7, 0x2e, 0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0, 0x1,
            0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95,
            0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0,
        ];
        let sd = SecurityDescriptor::read(&mut std::io::Cursor::new(buff)).unwrap();
        assert_eq!(
            sd,
            SecurityDescriptor {
                sbz1: 0,
                control: SecurityDescriptorControl::new().with_self_relative(true),
                owner_sid: Some(
                    SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001").unwrap()
                ),
                group_sid: Some(
                    SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001").unwrap()
                ),
                sacl: None,
                dacl: None
            }
        )
    }

    #[test]
    pub fn test_dacl_only_parse() {
        let buff = &[
            0x1, 0x0, 0x4, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14,
            0x0, 0x0, 0x0, 0x2, 0x0, 0x90, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x13, 0x24, 0x0, 0xff,
            0x1, 0x1f, 0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17,
            0x3d, 0xa7, 0x2e, 0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0,
            0x0, 0x13, 0x18, 0x0, 0xff, 0x1, 0x1f, 0x0, 0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5,
            0x20, 0x0, 0x0, 0x0, 0x20, 0x2, 0x0, 0x0, 0x0, 0x13, 0x14, 0x0, 0xff, 0x1, 0x1f, 0x0,
            0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0, 0x0, 0x13, 0x14, 0x0,
            0xa9, 0x0, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x13, 0x24, 0x0, 0xff, 0x1, 0x1f, 0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15,
            0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80,
            0xea, 0x3, 0x0, 0x0,
        ];
        let sd = SecurityDescriptor::read(&mut std::io::Cursor::new(buff)).unwrap();
        assert_eq!(
            sd,
            SecurityDescriptor {
                sbz1: 0,
                control: SecurityDescriptorControl::new()
                    .with_self_relative(true)
                    .with_dacl_auto_inherited(true)
                    .with_dacl_present(true),
                owner_sid: None,
                group_sid: None,
                sacl: None,
                dacl: ACL {
                    acl_revision: AclRevision::Nt4,
                    ace: vec![
                        ACE {
                            ace_flags: AceFlags::new()
                                .with_inherited(true)
                                .with_container_inherit(true)
                                .with_object_inherit(true),
                            value: AceValue::AccessAllowed(AccessAllowedAce {
                                access_mask: FileAccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                                sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001")
                                    .unwrap()
                            })
                        },
                        ACE {
                            ace_flags: AceFlags::new()
                                .with_inherited(true)
                                .with_container_inherit(true)
                                .with_object_inherit(true),
                            value: AceValue::AccessAllowed(AccessAllowedAce {
                                access_mask: FileAccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                                sid: SID::from_str(SID::S_ADMINISTRATORS).unwrap()
                            })
                        },
                        ACE {
                            ace_flags: AceFlags::new()
                                .with_inherited(true)
                                .with_container_inherit(true)
                                .with_object_inherit(true),
                            value: AceValue::AccessAllowed(AccessAllowedAce {
                                access_mask: FileAccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                                sid: SID::from_str(SID::S_LOCAL_SYSTEM).unwrap()
                            })
                        },
                        ACE {
                            ace_flags: AceFlags::new()
                                .with_inherited(true)
                                .with_container_inherit(true)
                                .with_object_inherit(true),
                            value: AceValue::AccessAllowed(AccessAllowedAce {
                                access_mask: FileAccessMask::from_bytes(0x1200a9u32.to_le_bytes()),
                                sid: SID::from_str(SID::S_EVERYONE).unwrap()
                            })
                        },
                        ACE {
                            ace_flags: AceFlags::new()
                                .with_inherited(true)
                                .with_container_inherit(true)
                                .with_object_inherit(true),
                            value: AceValue::AccessAllowed(AccessAllowedAce {
                                access_mask: FileAccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                                sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1002")
                                    .unwrap()
                            })
                        },
                    ]
                }
                .into()
            }
        )
    }

    const SID_STRING: &str = "S-1-5-21-782712087-4182988437-2163400469-1002";

    #[test]
    fn test_sid_to_from_string() {
        let sid_value: SID = SID {
            identifier_authority: 5,
            sub_authority: vec![21, 782712087, 4182988437, 2163400469, 1002],
        };
        assert_eq!(SID_STRING.parse::<SID>().unwrap(), sid_value);
        assert_eq!(sid_value.to_string(), SID_STRING);
    }
    #[test]
    fn test_sid_to_from_bin() {
        let sid_value = [
            0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e,
            0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xea, 0x3, 0x0, 0x0,
        ];
        let mut cursor = std::io::Cursor::new(&sid_value);
        assert_eq!(
            SID::read_le(&mut cursor).unwrap(),
            SID_STRING.parse().unwrap()
        );
    }
}
