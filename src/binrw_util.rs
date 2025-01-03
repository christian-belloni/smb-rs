use std::{io::prelude::*, string::FromUtf16Error};
use binrw::io::Write;
use core::fmt::{self, Write as _};
use binrw::{prelude::*, Endian};

/// Based on binrw::strings::NullWideString, but terminated by provided size rather than null char.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct SizedWideString(
    /// The raw wide byte string.
    pub Vec<u16>,
);

impl SizedWideString {
    /// In bytes.
    pub fn size(&self) -> u64 {
        self.0.len() as u64 * 2
    }

    /// In chars.
    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }
}

impl BinRead for SizedWideString {
    type Args<'a> = (u64,);

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        size_bytes: Self::Args<'_>,
    ) -> BinResult<Self> {
        // Size is in bytes, but we need to read in chars.
        assert!(size_bytes.0 % 2 == 0, "Size must be a multiple of 2");
        let size_chars = size_bytes.0 / 2;

        let mut values = Vec::with_capacity(size_chars as usize);

        for _ in 0..size_chars {
            let val = <u16>::read_options(reader, endian, ())?;
            values.push(val);
        };
        Ok(Self(values))
    }
}

impl BinWrite for SizedWideString {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.0.write_options(writer, endian, args)?;

        Ok(())
    }
}

impl From<SizedWideString> for Vec<u16> {
    fn from(s: SizedWideString) -> Self {
        s.0
    }
}

impl From<&str> for SizedWideString {
    fn from(s: &str) -> Self {
        Self(s.encode_utf16().collect())
    }
}

impl From<String> for SizedWideString {
    fn from(s: String) -> Self {
        Self(s.encode_utf16().collect())
    }
}

impl TryFrom<SizedWideString> for String {
    type Error = FromUtf16Error;

    fn try_from(value: SizedWideString) -> Result<Self, Self::Error> {
        String::from_utf16(&value.0)
    }
}

impl core::ops::Deref for SizedWideString {
    type Target = Vec<u16>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for SizedWideString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Display for SizedWideString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_utf16(&self.0, f, core::iter::once)
    }
}

impl fmt::Debug for SizedWideString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SizedWideString(\"")?;
        display_utf16(&self.0, f, char::escape_debug)?;
        write!(f, "\")")
    }
}

fn display_utf16<Transformer: Fn(char) -> O, O: Iterator<Item = char>>(
    input: &[u16],
    f: &mut fmt::Formatter<'_>,
    t: Transformer,
) -> fmt::Result {
    char::decode_utf16(input.iter().copied())
        .flat_map(|r| t(r.unwrap_or(char::REPLACEMENT_CHARACTER)))
        .try_for_each(|c| f.write_char(c))
}
