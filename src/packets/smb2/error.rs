use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug)]
pub struct ErrorResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,

    #[bw(try_calc = error_data.len().try_into())]
    _error_context_count: u8,

    #[br(assert(_reserved == 0))]
    #[bw(calc = 0)]
    _reserved: u8,

    _byte_count: u32,

    #[br(count = _error_context_count)]
    error_data: Vec<ErrorResponseContext>,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct ErrorResponseContext {
    // each context item should be aligned to 8 bytes,
    // relative to the start of the error context.
    // luckily, it appears after the header, which is, itself, aligned to 8 bytes.
    #[brw(align_before = 8)]
    #[bw(try_calc = error_data.len().try_into())]
    _error_data_length: u32,
    pub error_id: ErrorId,
    #[br(count = _error_data_length)]
    pub error_data: Vec<u8>,
}

#[binrw::binrw]
#[derive(Debug)]
#[brw(repr(u32))]
pub enum ErrorId {
    Default = 0,
    ShareRedirect = 0x72645253,
}
