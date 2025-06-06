//! Data structures for NDR64.
use binrw::prelude::*;

pub mod align;
pub use align::*;
pub mod arrays;
pub use arrays::*;
pub mod string;
pub use string::*;
pub mod ptr;
pub use ptr::*;

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
}
