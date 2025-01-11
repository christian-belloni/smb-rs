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
    pub fn date_time(&self) -> PrimitiveDateTime {
        let base = datetime!(1601-01-01 00:00:00);
        let duration = core::time::Duration::from_nanos(self.value * 100);
        base + duration
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
