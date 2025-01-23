use std::io::Cursor;

use crate::packets::smb2::{
    compressed::{self, *},
    message::*,
    negotiate::CompressionAlgorithm,
};
use binrw::prelude::*;

pub struct Decompressor<'a> {
    original: &'a CompressedMessage,
}

impl<'a> Decompressor<'a> {
    pub fn new(original: &'a CompressedMessage) -> Decompressor<'a> {
        Decompressor { original }
    }

    pub fn decompress(&self) -> Result<Message, Box<dyn std::error::Error>> {
        let method: Box<dyn DecompressionMethod> = match self.original {
            CompressedMessage::Unchained(_) => Box::new(UnchainedDecompression),
            CompressedMessage::Chained(_) => Box::new(ChainedDecompression),
        };
        let bytes = method.decompress(&self.original)?;
        let mut cursor = std::io::Cursor::new(bytes);
        Ok(Message::read(&mut cursor)?)
    }
}

trait DecompressionMethod {
    fn decompress(
        &self,
        compressed: &CompressedMessage,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    fn get_compression_algorithm(
        &self,
        algo: CompressionAlgorithm,
    ) -> Result<Box<dyn CompressionAlgorithmImpl>, &'static str> {
        Ok(match algo {
            CompressionAlgorithm::None => Box::new(NoneDecompression),
            CompressionAlgorithm::PatternV1 => Box::new(PatternV1Decompression),
            _ => Err("Unsupported compression algorithm")?,
        })
    }
}

struct UnchainedDecompression;

impl DecompressionMethod for UnchainedDecompression {
    fn decompress(
        &self,
        compressed: &CompressedMessage,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let compressed = match compressed {
            CompressedMessage::Unchained(c) => c,
            _ => Err("Expected Unchained message")?,
        };
        let mut data: Vec<u8> = Vec::<u8>::with_capacity(compressed.original_size as usize);
        self.get_compression_algorithm(compressed.compression_algorithm)?
            .decompress(&compressed.data, Some(compressed.original_size), &mut data)?;
        Ok(data)
    }
}

struct ChainedDecompression;

impl DecompressionMethod for ChainedDecompression {
    fn decompress(
        &self,
        compressed: &CompressedMessage,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let compressed = match compressed {
            CompressedMessage::Chained(c) => c,
            _ => Err("Expected Chained message")?,
        };
        let mut data = Vec::<u8>::with_capacity(compressed.original_size as usize);

        for item in compressed.items.iter() {
            let current_length_written = data.len();
            let end_of_decomression_target_slice = match item.original_size {
                Some(a) => a as usize,
                None => data.capacity() as usize,
            };
            self.get_compression_algorithm(item.compression_algorithm)?
                .decompress(
                    &item.payload_data,
                    item.original_size,
                    &mut data[current_length_written..end_of_decomression_target_slice],
                )?;
            // TODO: range should be more restricitve
        }

        Ok(data)
    }
}

trait CompressionAlgorithmImpl {
    fn decompress(
        &self,
        compressed: &Vec<u8>,
        original_size: Option<u32>,
        out: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>>;
}

struct NoneDecompression;

impl CompressionAlgorithmImpl for NoneDecompression {
    fn decompress(
        &self,
        compressed: &Vec<u8>,
        original_size: Option<u32>,
        out: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(original_size.is_none());

        out.copy_from_slice(compressed);
        Ok(())
    }
}

struct PatternV1Decompression;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct PatternV1Payload {
    pattern: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved1 == 0))]
    reserved1: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    repetitions: u32,
}

impl CompressionAlgorithmImpl for PatternV1Decompression {
    fn decompress(
        &self,
        compressed: &Vec<u8>,
        original_size: Option<u32>,
        out: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(original_size.is_none());
        assert!(compressed.len() == 8);
        let mut cursor = Cursor::new(&compressed);

        let parsed_payload = PatternV1Payload::read(&mut cursor)?;
        for i in 0..parsed_payload.repetitions as usize {
            out[i] = parsed_payload.pattern;
        }

        Ok(())
    }
}
