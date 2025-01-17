use super::encrypted::*;
use super::plain::*;
use binrw::prelude::*;

#[derive(BinRead, BinWrite, Debug)]
pub enum Message {
    Plain(PlainMessage),
    Encrypted(EncryptedMessage),
    // TODO: Compressed(CompressedMessage),
}
