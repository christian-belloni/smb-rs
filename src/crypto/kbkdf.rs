use std::error::Error;

use aes::cipher::typenum;
use hmac::{Hmac, Mac};
use rust_kbkdf::{
    kbkdf, CounterMode, InputType, KDFMode, PseudoRandomFunction, PseudoRandomFunctionKey,
    SpecifiedInput,
};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

pub fn kbkdf_hmacsha256(
    key: &[u8; 16],
    label: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // SP108-800-CTR-HMAC-SHA256; 128 bits; 32-bit counter.
    let key = HmacSha256KeyHandle { key: key.clone() };

    let mut prf = HmacSha256Prf::default();
    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });

    let input = InputType::SpecifiedInput(SpecifiedInput { label, context });

    let mut output = vec![0; 128 / 8];
    kbkdf(&mode, &input, &key, &mut prf, &mut output)?;

    Ok(output)
}

struct HmacSha256KeyHandle {
    key: [u8; 16],
}

impl PseudoRandomFunctionKey for HmacSha256KeyHandle {
    type KeyHandle = [u8; 16];

    fn key_handle(&self) -> &Self::KeyHandle {
        &self.key
    }
}

#[derive(Default)]
struct HmacSha256Prf {
    hmac: Option<HmacSha256>,
}

impl PseudoRandomFunction<'_> for HmacSha256Prf {
    type KeyHandle = [u8; 16];

    type PrfOutputSize = typenum::U32;

    type Error = String;

    fn init(
        &mut self,
        key: &'_ dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Self::Error> {
        assert!(self.hmac.is_none());
        self.hmac = Some(HmacSha256::new_from_slice(key.key_handle()).unwrap());
        Ok(())
    }

    fn update(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        self.hmac.as_mut().unwrap().update(msg);
        Ok(())
    }

    fn finish(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        let result = self.hmac.take().unwrap().finalize().into_bytes();
        out.copy_from_slice(&result);
        Ok(result.len())
    }
}
