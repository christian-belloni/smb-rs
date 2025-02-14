use thiserror::Error;

use crate::{connection::TransformError, packets::smb2::NegotiateDialect};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsupported dialect revision")]
    UnsupportedDialect(NegotiateDialect),
    #[error("Unexpected Message, {0}")]
    InvalidMessage(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Binrw Error: {0}")]
    BinaryError(#[from] binrw::Error),
    #[error("Client is not connected.")]
    NotConnectedError,
    #[error("Invalid state: {0}")]
    InvalidStateError(String),
    #[error("Unable to transform message: {0}")]
    TranformFailedError(TransformError),
}
