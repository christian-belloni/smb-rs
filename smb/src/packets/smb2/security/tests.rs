use super::*;
use std::str::FromStr;

use binrw::prelude::*;

#[test]
pub fn test_owner_group_parse() {
    let buff = &[
        0x1, 0x0, 0x0, 0x80, 0x14, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d,
        0xa7, 0x2e, 0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0, 0x1, 0x5,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95, 0x56,
        0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0,
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
        0x1, 0x0, 0x4, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x0,
        0x0, 0x0, 0x2, 0x0, 0x90, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x13, 0x24, 0x0, 0xff, 0x1, 0x1f,
        0x0, 0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e,
        0x95, 0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xe9, 0x3, 0x0, 0x0, 0x0, 0x13, 0x18, 0x0,
        0xff, 0x1, 0x1f, 0x0, 0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x20, 0x0, 0x0, 0x0, 0x20,
        0x2, 0x0, 0x0, 0x0, 0x13, 0x14, 0x0, 0xff, 0x1, 0x1f, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x5, 0x12, 0x0, 0x0, 0x0, 0x0, 0x13, 0x14, 0x0, 0xa9, 0x0, 0x12, 0x0, 0x1, 0x1, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13, 0x24, 0x0, 0xff, 0x1, 0x1f, 0x0,
        0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x15, 0x0, 0x0, 0x0, 0x17, 0x3d, 0xa7, 0x2e, 0x95,
        0x56, 0x53, 0xf9, 0x15, 0xdf, 0xf2, 0x80, 0xea, 0x3, 0x0, 0x0,
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
                        value: AceValue::AccessAllowed(AccessAce {
                            access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                            sid: SID::from_str("S-1-5-21-782712087-4182988437-2163400469-1001")
                                .unwrap()
                        })
                    },
                    ACE {
                        ace_flags: AceFlags::new()
                            .with_inherited(true)
                            .with_container_inherit(true)
                            .with_object_inherit(true),
                        value: AceValue::AccessAllowed(AccessAce {
                            access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                            sid: SID::from_str(SID::S_ADMINISTRATORS).unwrap()
                        })
                    },
                    ACE {
                        ace_flags: AceFlags::new()
                            .with_inherited(true)
                            .with_container_inherit(true)
                            .with_object_inherit(true),
                        value: AceValue::AccessAllowed(AccessAce {
                            access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
                            sid: SID::from_str(SID::S_LOCAL_SYSTEM).unwrap()
                        })
                    },
                    ACE {
                        ace_flags: AceFlags::new()
                            .with_inherited(true)
                            .with_container_inherit(true)
                            .with_object_inherit(true),
                        value: AceValue::AccessAllowed(AccessAce {
                            access_mask: AccessMask::from_bytes(0x1200a9u32.to_le_bytes()),
                            sid: SID::from_str(SID::S_EVERYONE).unwrap()
                        })
                    },
                    ACE {
                        ace_flags: AceFlags::new()
                            .with_inherited(true)
                            .with_container_inherit(true)
                            .with_object_inherit(true),
                        value: AceValue::AccessAllowed(AccessAce {
                            access_mask: AccessMask::from_bytes(0x1f01ffu32.to_le_bytes()),
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
