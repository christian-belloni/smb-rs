#[cfg(not(any(feature = "async", feature = "sync")))]
compile_error!("You must enable at least one of the features: 'async' or 'sync.");

pub mod compression;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod msg_handler;
pub mod packets;
pub mod resource;
pub mod session;
pub mod tree;

pub use connection::Connection;
pub use error::Error;

type Result = std::result::Result<(), crate::Error>;
