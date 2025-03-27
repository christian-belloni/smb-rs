use super::ResourceHandle;
use crate::sync_helpers::*;
use crate::{
    packets::{fscc::*, smb2::*},
    Error,
};
use futures_core::Stream;
use maybe_async::*;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A directory resource on the server.
/// This is used to query the directory for its contents,
/// and may not be created directly -- but via [Resource][super::Resource], opened
/// from a [Tree][crate::tree::Tree]
pub struct Directory {
    pub handle: ResourceHandle,
    access: DirAccessMask,
}

impl Directory {
    pub fn new(handle: ResourceHandle, access: DirAccessMask) -> Self {
        Directory { handle, access }
    }

    /// An internal method that performs a query on the directory.
    /// it may be used to query information, but it is best to use
    #[maybe_async]
    async fn send_query<T>(&self, pattern: &str, restart: bool) -> crate::Result<Vec<T>>
    where
        T: QueryDirectoryInfoValue,
    {
        if !self.access.list_directory() {
            return Err(Error::MissingPermissions("file_list_directory".to_string()));
        }

        log::debug!("Querying directory {}", self.handle.name());

        let response = self
            .handle
            .send_receive(Content::QueryDirectoryRequest(QueryDirectoryRequest {
                file_information_class: T::CLASS_ID,
                flags: QueryDirectoryFlags::new().with_restart_scans(restart),
                file_index: 0,
                file_id: self.handle.file_id,
                output_buffer_length: 0x10000,
                file_name: pattern.into(),
            }))
            .await?;

        Ok(response
            .message
            .content
            .to_querydirectoryresponse()?
            .read_output()?)
    }

    /// Asynchronously iterates over the directory contents, using the provided pattern and infromation type.
    /// # Arguments
    /// * `pattern` - The pattern to match against the file names in the directory. Use wildcards like `*` and `?` to match multiple files.
    /// * `info` - The information type to query. This is a trait object that implements the [QueryDirectoryInfoValue] trait.
    /// # Returns
    /// * An iterator over the directory contents, yielding [QueryDirectoryInfoValue] objects.
    #[cfg(feature = "async")]
    pub fn query_directory<T>(this: &Arc<Self>, pattern: &str) -> QueryDirectoryStream<T>
    where
        T: QueryDirectoryInfoValue,
    {
        QueryDirectoryStream::new(this.clone(), pattern.to_string())
    }

    #[cfg(not(feature = "async"))]
    pub fn query_directory<T>(
        &mut self,
        pattern: &str,
    ) -> impl Iterator<Item = crate::Result<T>> + '_
    where
        T: QueryDirectoryInfoValue,
    {
        let mut first = true;
        std::iter::from_fn(move || {
            let result = self.send_query::<T>(pattern, first);
            first = false; // Ensure subsequent calls know it's not the first request

            match result {
                Ok(items) => {
                    if items.is_empty() {
                        None
                    } else {
                        Some(Ok(items.into_iter()))
                    }
                }
                Err(Error::UnexpectedMessageStatus(Status::NoMoreFiles)) => None,
                Err(e) => Some(Err(e)),
            }
        })
        .flatten()
    }

    #[maybe_async]
    pub async fn query_quota_info(&self, info: QueryQuotaInfo) -> crate::Result<QueryQuotaInfo> {
        Ok(self
            .handle
            .query_common(QueryInfoRequest {
                info_type: InfoType::Quota,
                info_class: Default::default(),
                output_buffer_length: 1024,
                additional_info: AdditionalInfo::new(),
                flags: QueryInfoFlags::new()
                    .with_restart_scan(true)
                    .with_return_single_entry(true),
                file_id: self.handle.file_id,
                data: GetInfoRequestData::Quota(info),
            })
            .await?
            .unwrap_quota())
    }

    /// Sets the quota information for the current file.
    /// # Arguments
    /// * `info` - The information to set - a [QueryQuotaInfo].
    #[maybe_async]
    pub async fn set_quota_info(&self, info: QueryQuotaInfo) -> crate::Result<()> {
        self.handle
            .set_info_common(
                info,
                SetInfoClass::Quota(Default::default()),
                Default::default(),
            )
            .await
    }
}

impl Deref for Directory {
    type Target = ResourceHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for Directory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

pub struct QueryDirectoryStream<T> {
    receiver: tokio::sync::mpsc::Receiver<crate::Result<T>>,
    notify_fetch_next: Arc<tokio::sync::Notify>,
}

impl<T> QueryDirectoryStream<T>
where
    T: QueryDirectoryInfoValue,
{
    pub fn new(directory: Arc<Directory>, pattern: String) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(1024);
        let notify_fetch_next = Arc::new(tokio::sync::Notify::new());
        {
            let notify_fetch_next = notify_fetch_next.clone();

            tokio::spawn(async move {
                Self::fetch_loop(directory, pattern, sender, notify_fetch_next.clone()).await;
            });
        }
        Self {
            receiver,
            notify_fetch_next,
        }
    }

    async fn fetch_loop(
        directory: Arc<Directory>,
        pattern: String,
        sender: mpsc::Sender<crate::Result<T>>,
        notify_fetch_next: Arc<tokio::sync::Notify>,
    ) {
        let mut is_first = true;
        loop {
            let result = directory.send_query::<T>(&pattern, is_first).await;
            is_first = false;

            match result {
                Ok(items) => {
                    for item in items {
                        if sender.send(Ok(item)).await.is_err() {
                            return; // Receiver dropped
                        }
                    }
                }
                Err(Error::UnexpectedMessageStatus(Status::NoMoreFiles)) => {
                    break; // No more files
                }
                Err(e) => {
                    if sender.send(Err(e)).await.is_err() {
                        return; // Receiver dropped
                    }
                }
            }

            // Notify the stream that a new batch is available
            notify_fetch_next.notify_waiters();
            notify_fetch_next.notified().await;
        }
    }
}

impl<T> Stream for QueryDirectoryStream<T>
where
    T: QueryDirectoryInfoValue + Unpin + Send,
{
    type Item = crate::Result<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        return match this.receiver.poll_recv(cx) {
            Poll::Ready(Some(value)) => {
                if this.receiver.is_empty() {
                    this.notify_fetch_next.notify_waiters() // Notify that batch is done
                }
                Poll::Ready(Some(value))
            }
            Poll::Ready(None) => Poll::Ready(None), // Stream is closed!
            Poll::Pending => Poll::Pending,
        };
    }
}
