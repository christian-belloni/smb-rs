//! Data structures for NDR64.
use binrw::prelude::*;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

pub const NDR64_PADDING: usize = 8;

/// A trait for types that are aligned according to NDR64 rules.
pub trait NdrAligned {}

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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import_raw(args: <E as BinRead>::Args<'_>))]
#[bw(import_raw(args: <E as BinWrite>::Args<'_>))]
pub struct NdrString<E, const SIZE: u32 = 0>
where
    E: BinRead + BinWrite + 'static,
    for<'a> <E as BinRead>::Args<'a>: Clone,
    for<'a> <E as BinWrite>::Args<'a>: Clone,
{
    // This is only for non-conformant strings -
    // strings that have a variable allocation size.
    // for conformant strings, const SIZE is non-zero!
    #[bw(if(SIZE == 0), calc = Some(data.len() as u64))]
    #[br(if(SIZE == 0))]
    alloc_length: Option<u64>,

    #[bw(calc = 0)]
    #[br(assert(offset == 0))] // TODO: Support non-zero offsets!
    offset: u64,
    #[bw(calc = data.len() as u64)]
    #[br(assert((SIZE == 0 || actual_count < SIZE as u64) ||
                (SIZE != 0 && actual_count < alloc_length.unwrap() as u64)))]
    actual_count: u64,
    #[br(count = actual_count, args { inner: args })]
    #[bw(args_raw(args))]
    pub data: NdrAlign<Vec<E>>,
}

impl<E> NdrAligned for NdrString<E>
where
    E: BinRead + BinWrite + 'static,
    for<'a> <E as BinRead>::Args<'a>: Clone,
    for<'a> <E as BinWrite>::Args<'a>: Clone,
{
}

// String to NdrString<u16> conversion:
impl FromStr for NdrString<u16, 0> {
    type Err = std::string::FromUtf16Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data: Vec<u16> = s
            .encode_utf16()
            .chain(
                std::iter::once(0), // Null terminator
            )
            .collect();
        Ok(Self {
            data: NdrAlign { value: data.into() },
        })
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(array_count: u64, inner_args: <E as BinRead>::Args<'_>))]
#[bw(import_raw(args: <E as BinWrite>::Args<'_>))]
pub struct NdrArray<E>
where
    E: BinRead + BinWrite + 'static,
    for<'a> <E as BinRead>::Args<'a>: Clone,
    for<'a> <E as BinWrite>::Args<'a>: Clone,
{
    #[br(count = array_count, args { inner: inner_args })]
    #[bw(args_raw(args))]
    pub data: Vec<NdrAlign<E>>,
}

impl<E> NdrAligned for NdrArray<E>
where
    E: BinRead + BinWrite + 'static,
    for<'a> <E as BinRead>::Args<'a>: Clone,
    for<'a> <E as BinWrite>::Args<'a>: Clone,
{
}

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
    #[brw(align_after = NDR64_PADDING)]
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
    fn test_string_ptr() {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        struct TestNdrStringPtr {
            string: NdrPtr<NdrString<u16>>,
            aligned: u32,
        }

        let data = TestNdrStringPtr {
            string: r"\\localhostt".parse::<NdrString<u16>>().unwrap().into(),
            aligned: ALIGNED_MAGIC,
        };

        let mut cursor = Cursor::new(vec![]);
        data.write_le(&mut cursor).unwrap();
        let write_result = cursor.into_inner();
        assert_eq!(
            write_result,
            [
                0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x5c, 0x0, 0x5c, 0x0, 0x6c, 0x0, 0x6f, 0x0, 0x63, 0x0, 0x61, 0x0, 0x6c, 0x0, 0x68,
                0x0, 0x6f, 0x0, 0x73, 0x0, 0x74, 0x0, 0x74, 0x0, 0x0, 0x0, // string value
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // alignment padding
                0x78, 0x56, 0x34, 0x12 // aligned value
            ]
        );
    }

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
            aligned: ALIGNED_MAGIC,
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
