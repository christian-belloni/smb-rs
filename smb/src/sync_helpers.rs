use std::sync::LockResult;
#[cfg(not(feature = "async"))]
pub use std::{
    cell::OnceCell,
    sync::{Mutex, RwLock},
};
///! This is a helper module that allows easy access and usage of
/// Async/Multi-threaded features in the library, according to the
/// features enabled.

#[cfg(feature = "async")]
pub use tokio::sync::{Mutex, OnceCell};

/// A wrapper for [tokio::sync::RwLock] that mocks the behavior of [std::sync::RwLock].
#[cfg(feature = "async")]
#[derive(Debug, Default)]
pub struct RwLock<T: ?Sized> {
    inner: tokio::sync::RwLock<T>,
}

impl<T> RwLock<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self {
            inner: tokio::sync::RwLock::new(value),
        }
    }

    #[inline]
    pub async fn read(&self) -> LockResult<tokio::sync::RwLockReadGuard<'_, T>> {
        Ok(self.inner.read().await)
    }

    #[inline]
    pub async fn write(&self) -> LockResult<tokio::sync::RwLockWriteGuard<'_, T>> {
        Ok(self.inner.write().await)
    }
}
