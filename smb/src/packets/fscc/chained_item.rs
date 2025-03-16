//! A genric utility struct to wrap "chained"-encoded entries.
//! Many fscc-query structs have a common "next entry offset" field,
//! which is used to chain multiple entries together.
//! This struct wraps the value, and the offset, and provides a way to iterate over them.
//! See [ChainedItem<T>::write_chained] to see how to write this type when in a list.
//!
use std::ops::Deref;

use crate::packets::binrw_util::prelude::*;
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
#[bw(import(last: bool))]
pub struct ChainedItem<T, const OFFSET_PAD: u32 = 4>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(assert(next_entry_offset.value % OFFSET_PAD == 0))]
    #[bw(calc = PosMarker::default())]
    next_entry_offset: PosMarker<u32>,
    pub value: T,
    #[br(seek_before = next_entry_offset.seek_relative(true))]
    #[bw(if(!last))]
    #[bw(align_before = OFFSET_PAD)]
    #[bw(write_with = PosMarker::write_roff, args(&next_entry_offset))]
    __: (),
}

impl<T, const OFFSET_PAD: u32> ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    pub fn new(value: T) -> Self {
        Self::from(value)
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    #[binrw::writer(writer, endian)]
    pub fn write_chained(value: &Vec<ChainedItem<T, OFFSET_PAD>>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            item.write_options(writer, endian, (i == value.len() - 1,))?;
        }
        Ok(())
    }
}

impl<T, const OFFSET_PAD: u32> PartialEq for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite + PartialEq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T, const OFFSET_PAD: u32> Eq for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite + Eq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
}

impl<T, const OFFSET_PAD: u32> Deref for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T, const OFFSET_PAD: u32> From<T> for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(value: T) -> Self {
        Self { value, __: () }
    }
}
