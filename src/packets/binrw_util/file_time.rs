//! FileTime is a wrapper around a u64 that represents a file time,
//! According to the FILETIME structure [MS-DTYP] 2.3.3.

use std::fmt::Display;
use std::ops::Deref;

use binrw::prelude::*;
use time::macros::datetime;
use time::PrimitiveDateTime;

#[derive(BinRead, BinWrite, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileTime {
    /// 100-nanosecond intervals since January 1, 1601 (UTC)
    value: u64,
}

impl FileTime {
    const EPOCH: PrimitiveDateTime = datetime!(1601-01-01 00:00:00);
    const SCALE: u64 = 100;

    pub fn date_time(&self) -> PrimitiveDateTime {
        let duration = core::time::Duration::from_nanos(self.value * Self::SCALE);
        Self::EPOCH + duration
    }
}

impl Display for FileTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.date_time().fmt(f)
    }
}

impl std::fmt::Debug for FileTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FileTime").field(&self.date_time()).finish()
    }
}

impl From<u64> for FileTime {
    fn from(value: u64) -> Self {
        Self { value }
    }
}

impl From<PrimitiveDateTime> for FileTime {
    fn from(dt: PrimitiveDateTime) -> Self {
        let duration = dt - Self::EPOCH;
        Self {
            value: duration.whole_nanoseconds() as u64 / Self::SCALE,
        }
    }
}

impl Default for FileTime {
    fn default() -> Self {
        Self { value: 0 }
    }
}

impl Deref for FileTime {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use time::macros::datetime;

    const TEST_VAL1_U64: u64 = 133818609802776324;
    const TEST_VAL1_DT: PrimitiveDateTime = datetime!(2025-01-20 15:36:20.277632400);

    #[test]
    pub fn test_file_time_from_u64_correct() {
        assert_eq!(FileTime::from(TEST_VAL1_U64).date_time(), TEST_VAL1_DT)
    }

    #[test]
    pub fn test_file_time_from_datetime_correct() {
        assert_eq!(*FileTime::from(TEST_VAL1_DT), TEST_VAL1_U64)
    }
}
