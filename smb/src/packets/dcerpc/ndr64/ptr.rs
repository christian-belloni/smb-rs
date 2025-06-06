use std::ops::{Deref, DerefMut};

use super::align::*;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import_raw(args: <T as BinRead>::Args<'_>))]
#[bw(import_raw(args: <T as BinWrite>::Args<'_>))]
pub struct NdrPtr<T>
where
    for<'a, 'b> T: BinRead + BinWrite,
{
    // For unique pointers, this is the default.
    #[bw(calc = {if value.is_some() {Self::REF_ID_UNIQUE_DEFAULT} else {Self::NULL_PTR_REF_ID}})]
    ref_id: u64,
    #[br(if(ref_id != Self::NULL_PTR_REF_ID))]
    #[brw(args_raw(args))]
    pub value: NdrAlign<Option<T>>,
}

impl<T> NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    pub const REF_ID_UNIQUE_DEFAULT: u64 = 0x20000;
    pub const NULL_PTR_REF_ID: u64 = 0x0;
}

impl<T> NdrAligned for NdrPtr<T> where T: BinRead + BinWrite {}

impl<T> Deref for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> DerefMut for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T> From<T> for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    fn from(value: T) -> Self {
        Self::from(Some(value))
    }
}

impl<T> From<Option<T>> for NdrPtr<T>
where
    T: BinRead + BinWrite,
{
    fn from(value: Option<T>) -> Self {
        Self {
            value: NdrAlign { value },
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_nullptr() {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        struct TestNdrNullPtr {
            null_ptr: NdrPtr<u32>,
            aligned: u32,
        }

        let data = TestNdrNullPtr {
            null_ptr: None.into(),
            aligned: 0x12345678,
        };

        let mut cursor = Cursor::new(vec![]);
        data.write_le(&mut cursor).unwrap();
        let write_result = cursor.into_inner();
        assert_eq!(
            write_result,
            [
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // null pointer, no data!
                0x78, 0x56, 0x34, 0x12 // aligned value
            ]
        );
    }
}
