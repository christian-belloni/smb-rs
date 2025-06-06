use binrw::prelude::*;
use std::ops::{Deref, DerefMut};

pub const NDR64_ALIGNMENT: usize = 8;

/// A trait for types that are aligned according to NDR64 rules.
pub trait NdrAligned {}
/// Writes the inner value, and aligns the writer to
/// the NDR alignment AFTER writing the value.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import_raw(args: <T as BinRead>::Args<'_>))]
#[bw(import_raw(args: <T as BinWrite>::Args<'_>))]
pub struct NdrAlign<T>
where
    T: BinRead + BinWrite,
{
    #[brw(align_after = NDR64_ALIGNMENT)]
    #[brw(args_raw(args))]
    pub value: T,
}

impl<T> Deref for NdrAlign<T>
where
    T: BinRead + BinWrite,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> DerefMut for NdrAlign<T>
where
    T: BinRead + BinWrite,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T> NdrAligned for NdrAlign<T> where T: BinRead + BinWrite {}

impl<T> From<T> for NdrAlign<T>
where
    T: BinRead + BinWrite,
{
    fn from(value: T) -> Self {
        Self { value }
    }
}

impl<T> Default for NdrAlign<T>
where
    T: BinRead + BinWrite + Default,
{
    fn default() -> Self {
        T::default().into()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const ALIGNED_MAGIC: u32 = 0x12345678;

    #[test]
    fn test_align() {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        struct TestNdrAlign {
            unalign: u8,
            unalign2: u16,
            should_align: NdrAlign<u32>,
            aligned: u32,
        }

        let data = TestNdrAlign {
            unalign: 0,
            unalign2: 0,
            should_align: NdrAlign { value: 0 },
            aligned: ALIGNED_MAGIC,
        };

        let mut cursor = Cursor::new(vec![]);
        data.write_le(&mut cursor).unwrap();

        let write_result = cursor.into_inner();
        assert_eq!(
            write_result,
            [
                0x00, // unalign
                0x00, 0x00, // unalign2
                0x00, 0x00, 0x00, 0x00, // should_align (uninitialized)
                0x00, // shoukd_align's padding
                0x78, 0x56, 0x34, 0x12 // aligned
            ]
        );

        let mut cursor = Cursor::new(&write_result);
        let read_result: TestNdrAlign = TestNdrAlign::read_le(&mut cursor).unwrap();
        assert_eq!(
            read_result,
            TestNdrAlign {
                unalign: 0,
                unalign2: 0,
                should_align: NdrAlign { value: 0 },
                aligned: ALIGNED_MAGIC
            }
        )
    }
}
