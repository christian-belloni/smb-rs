use std::{fmt::Display, io::Cursor, str::FromStr};

use binrw::prelude::*;
use rand::{rngs::OsRng, Rng};

/// Represents a standard, 16-byte GUID.
#[derive(BinRead, BinWrite, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct Guid(u32, u16, u16, [u8; 8]);

impl Guid {
    pub fn gen() -> Self {
        let mut rng = OsRng;
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        Self::try_from(&bytes).unwrap()
    }

    pub const MAX: Guid = Guid {
        0: u32::MAX,
        1: u16::MAX,
        2: u16::MAX,
        3: [u8::MAX; 8],
    };
}

impl From<[u8; 16]> for Guid {
    fn from(value: [u8; 16]) -> Self {
        Self::try_from(&value).unwrap()
    }
}

impl TryFrom<&[u8; 16]> for Guid {
    type Error = binrw::Error;

    fn try_from(value: &[u8; 16]) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(value);
        Guid::read(&mut cursor)
    }
}

impl FromStr for Guid {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Self::default();
        let components = s.split('-').collect::<Vec<&str>>();
        if components.len() != 5 {
            return Err(());
        }

        // little endian string of 4 bytes, read component in reverse order:
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(
            &u32::from_str_radix(components[0], 16)
                .map_err(|_| ())?
                .to_be_bytes(),
        );
        result.0 = u32::from_be_bytes(bytes);

        // 2 byte components, x2:
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(
            &u16::from_str_radix(components[1], 16)
                .map_err(|_| ())?
                .to_be_bytes(),
        );
        result.1 = u16::from_be_bytes(bytes);
        bytes.copy_from_slice(
            &u16::from_str_radix(components[2], 16)
                .map_err(|_| ())?
                .to_be_bytes(),
        );
        result.2 = u16::from_be_bytes(bytes);

        // The rest are 2 byte components, in big endian, and then 6 more bytes:
        result.3[..2].copy_from_slice(
            &u16::from_str_radix(components[3], 16)
                .map_err(|_| ())?
                .to_be_bytes(),
        );
        for i in 0..6 {
            result.3[i + 2] =
                u8::from_str_radix(&components[4][i * 2..i * 2 + 2], 16).map_err(|_| ())?;
        }
        Ok(result)
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print first fields in little endian, and the rest in big endian:
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:12x}",
            self.0,
            self.1,
            self.2,
            self.3[0],
            self.3[1],
            self.3[2..]
                .iter()
                .fold(0u64, |acc, &x| (acc << 8) + x as u64)
        )
    }
}

impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GUID_STR: &str = "065eadf1-6daf-1543-b04f-10e69084c9ae";
    const PARSED_GUID_VALUE: Guid = Guid(
        0x065eadf1,
        0x6daf,
        0x1543,
        [0xb0, 0x4f, 0x10, 0xe6, 0x90, 0x84, 0xc9, 0xae],
    );
    const TEST_GUID_BYTES: [u8; 16] = [
        0xf1u8, 0xad, 0x5e, 0x06, 0xaf, 0x6d, 0x43, 0x15, 0xb0, 0x4f, 0x10, 0xe6, 0x90, 0x84, 0xc9,
        0xae,
    ];

    #[test]
    pub fn test_guid_parse_string() {
        let guid = TEST_GUID_STR.parse::<Guid>().unwrap();
        assert_eq!(guid, PARSED_GUID_VALUE);
        assert_eq!(guid.to_string(), TEST_GUID_STR);
    }

    #[test]
    pub fn test_guid_parse_bytes() {
        assert_eq!(Guid::try_from(&TEST_GUID_BYTES).unwrap(), PARSED_GUID_VALUE);
    }

    #[test]
    pub fn test_guid_write_bytes() {
        let mut cursor = Cursor::new(Vec::new());
        PARSED_GUID_VALUE.write(&mut cursor).unwrap();
        assert_eq!(cursor.into_inner(), TEST_GUID_BYTES);
    }
}
