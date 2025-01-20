//! Compressed messages

use binrw::prelude::*;
use binrw::io::TakeSeekExt;
use super::negotiate::CompressionAlgorithm;

pub enum CompressedHeader {
    Unchained(CompressedUnchainedHeader),
    Chained(CompressedChainedHeader)
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\xfcSMB"), little)]
pub struct CompressedUnchainedHeader {
    original_compressed_segment_size: u32,
    // The same as the negotiation, but must be set.
    #[brw(assert(!matches!(compression_algorithm, CompressionAlgorithm::None)))]
    compression_algorithm: CompressionAlgorithm,
    #[br(assert(flags == 0))]
    #[bw(calc = 0)]
    flags: u16,
    offset: u32
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(magic(b"\xfcSMB"), little)]
pub struct CompressedChainedHeader {
    original_compressed_segment_size: u32,
    compression_algorithm: CompressionAlgorithm,
    flags: u16,
    length: u32,
    // Only present if algorithms require it.
    #[brw(if(compression_algorithm.original_payload_size_required()))]
    original_payload_size: Option<u32>,
    #[br(map_stream = |s| s.take_seek(length.into()), parse_with = binrw::helpers::until_eof)]
    payload_data: CompressedChainedData
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(compression_algorithm: CompressionAlgorithm))]
pub enum CompressedChainedData {
    #[br(pre_assert(compression_algorithm == CompressionAlgorithm::PatternV1))]
    PatternV1Payload(PatternV1Payload),
}