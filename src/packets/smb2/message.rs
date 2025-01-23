use super::compressed::*;
use super::encrypted::*;
use super::plain::*;
use binrw::prelude::*;

#[derive(BinRead, BinWrite, Debug)]
#[brw(little)]
pub enum Message {
    Plain(PlainMessage),
    Encrypted(EncryptedMessage),
    Compressed(CompressedMessage),
}
