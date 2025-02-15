#[cfg(not(feature = "async"))]
pub use std::{
    cell::OnceCell,
    sync::{Mutex, RwLock},
};
///! This is a helper module that allows easy access and usage of
/// Async/Multi-threaded features in the library, according to the
/// features enabled.

#[cfg(feature = "async")]
pub use tokio::sync::{OnceCell, RwLock, Mutex};
