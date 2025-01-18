use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
// TODO: Use wherever this is relevant (create?)
pub struct FileId {
    persistent: u64,
    volatile: u64,
}