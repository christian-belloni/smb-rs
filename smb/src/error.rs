use std::{num::TryFromIntError, sync::PoisonError};

use thiserror::Error;

use crate::{
    connection::TransformError,
    packets::smb2::{Command, ErrorResponse, NegotiateDialect, Status},
    sync_helpers::AcquireError,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unsupported dialect revision")]
    UnsupportedDialect(NegotiateDialect),
    #[error("Unexpected Message, {0}")]
    InvalidMessage(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Binrw Error: {0}")]
    BinRWError(#[from] binrw::Error),
    #[error("Int parsing Error: {0}")]
    ParsingError(#[from] TryFromIntError),
    #[error("Client is not connected.")]
    NotConnected,
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Unable to transform message: {0}")]
    TranformFailed(TransformError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),
    #[error("Negotiation error: {0}")]
    NegotiationError(String),
    #[error("Signature verification failed!")]
    SignatureVerificationFailed,
    #[error("Unexpected message status: {0}")]
    UnexpectedMessageStatus(Status),
    #[error("Server returned an error message with status {0}.")]
    ReceivedErrorMessage(Status, ErrorResponse),
    #[error("Unexpected command: {0}")]
    UnexpectedCommand(Command),
    #[error("Missing permissions to perform {0}")]
    MissingPermissions(String),
    #[error("Sspi error: {0}")]
    SspiError(#[from] sspi::Error),
    #[error("DER error: {0}")]
    DerError(#[from] der::Error),
    #[error("Unsupported authentication mechanism: {0}")]
    UnsupportedAuthenticationMechanism(String),
    #[error("Compression error: {0}")]
    CompressionError(#[from] crate::compression::CompressionError),
    #[error("Username error: {0}")]
    UsernameError(String),
    #[error("Message processing failed. {0}")]
    MessageProcessingError(String),
    #[error("Operation timed out: {0}, took >{1:?}")]
    OperationTimeout(String, std::time::Duration),
    #[error("Lock error.")]
    LockError,
    #[cfg(feature = "async")]
    #[error("Task join error.")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Acquire Error: {0}")]
    AcquireError(#[from] AcquireError),
    #[cfg(feature = "sync")]
    #[error("Thread join error: {0}")]
    JoinError(String),
    #[cfg(feature = "sync")]
    #[error("Channel recv error.")]
    ChannelRecvError(#[from] std::sync::mpsc::RecvError),
    #[error("Unexpected message with ID {0} (exp {1}).")]
    UnexpectedMessageId(u64, u64),
    #[error("Expected info of type {0} but got {1}")]
    UnexpectedInformationType(u8, u8),
    #[error("Invalid address {0}")]
    InvalidAddress(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::LockError
    }
}
