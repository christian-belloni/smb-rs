use super::align::*;
use binrw::prelude::*;

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
