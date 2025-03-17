//! This module contains the implementation for the async worker(s).
//!
//! Depending on the crate configuration, one of the two backends will be used:
//! - async_backend for async workers
//! - threading_backend for sync workers
//!
//! The effective backend is exported as [AsyncWorker] from this module.

#[cfg(feature = "async")]
pub mod async_backend;
pub mod backend_trait;
pub mod base;
#[cfg(feature = "sync")]
pub mod threading_backend;
#[cfg(feature = "async")]
pub use async_backend::AsyncBackend;
use base::*;
#[cfg(feature = "sync")]
pub use threading_backend::ThreadingBackend as AsyncBackend;

pub type AsyncWorker = MultiWorkerBase<AsyncBackend>;
