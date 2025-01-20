use std::fmt::Display;

use binrw::prelude::*;
use time::macros::datetime;
use time::PrimitiveDateTime;

#[derive(BinRead, BinWrite, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileTime {
    /// 100-nanosecond intervals since January 1, 1601 (UTC),
    /// according to the FILETIME structure [MS-DTYP] 2.3.3.
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
