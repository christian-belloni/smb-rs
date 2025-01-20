//! Cancel Request

use binrw::prelude::*;

#[binrw::binrw]
pub struct CancelRequest {
    #[br(assert(structure_size == 4))]
    #[bw(calc = 4)]
    structure_size: u16,
    #[br(assert(reserved == 0))]
    #[bw(calc = 0)]
    reserved: u16,
}

impl Default for CancelRequest {
    fn default() -> Self {
        CancelRequest { }
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn test_cancel_req_write() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let cancel_req = CancelRequest::default();
        cancel_req.write_le(&mut cursor).unwrap();
        assert_eq!(
            cursor.into_inner(),
            [
                0x4, 0x0, 0x0, 0x0
            ]
        )
    }
}