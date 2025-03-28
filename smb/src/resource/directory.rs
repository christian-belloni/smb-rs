use super::ResourceHandle;
use crate::msg_handler::{MessageHandler, ReceiveOptions};
use crate::sync_helpers::Mutex;
use crate::{
    packets::{fscc::*, smb2::*},
    Error,
};
use maybe_async::*;
use std::ops::{Deref, DerefMut};
#[cfg(feature = "async")]
use std::sync::Arc;

/// A directory resource on the server.
/// This is used to query the directory for its contents,
/// and may not be created directly -- but via [Resource][super::Resource], opened
/// from a [Tree][crate::tree::Tree]
pub struct Directory {
    pub handle: ResourceHandle,
    access: DirAccessMask,
    /// This lock prevents iterating the directory twice at the same time.
    /// This is required since query directory state is tied to the handle of
    /// the directory (hence, to this structure's instance).
    query_lock: Mutex<()>,
}

impl Directory {
    pub fn new(handle: ResourceHandle, access: DirAccessMask) -> Self {
        Directory {
            handle,
            access,
            query_lock: Default::default(),
        }
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
    /// * `info` - The information type to query. This is a trait object that implements the [`QueryDirectoryInfoValue`] trait.
    /// # Returns
    /// * An iterator over the directory contents, yielding [`QueryDirectoryInfoValue`] objects.
    /// # Returns
    /// [`QueryDirectoryStream`] - Which implements [Stream] and can be used to iterate over the directory contents.
    /// # Notes
    /// * **IMPORTANT** Calling this method BLOCKS ANY ADDITIONAL CALLS to this method on THIS structure instance.
    /// Hence, you should not call this method on the same instance from multiple threads. This is for thread safety,
    /// since SMB2 does not allow multiple queries on the same handle at the same time. Re-open the directory and
    /// create a new instance of this structure to query the directory again.
    /// * You must use [`futures_util::StreamExt`] to consume the stream.
    /// See [https://tokio.rs/tokio/tutorial/streams] for more information on how to use streams.
    #[cfg(feature = "async")]
    pub async fn query_directory<'a, T>(
        this: &'a Arc<Self>,
        pattern: &str,
    ) -> crate::Result<iter_stream::QueryDirectoryStream<'a, T>>
    where
        T: QueryDirectoryInfoValue,
    {
        iter_stream::QueryDirectoryStream::new(this, pattern.to_string()).await
    }

    /// Synchronously iterates over the directory contents, using the provided pattern and infromation type.
    /// # Arguments
    /// * `pattern` - The pattern to match against the file names in the directory. Use wildcards like `*` and `?` to match multiple files.
    /// # Returns
    /// * An iterator over the directory contents, yielding [`QueryDirectoryInfoValue`] objects.
    /// # Notes
    /// * **IMPORTANT**: Calling this method BLOCKS ANY ADDITIONAL CALLS to this method on THIS structure instance.
    /// Hence, you should not call this method on the same instance from multiple threads. This is for safety,
    /// since SMB2 does not allow multiple queries on the same handle at the same time.
    #[cfg(not(feature = "async"))]
    pub fn query_directory<'a, T>(
        &'a self,
        pattern: &str,
    ) -> crate::Result<iter_sync::QueryDirectoryIterator<'a, T>>
    where
        T: QueryDirectoryInfoValue,
    {
        iter_sync::QueryDirectoryIterator::new(self, pattern.to_string())
    }

    /// Watches the directory for changes.
    /// # Arguments
    /// * `filter` - The filter to use for the changes. This is a bitmask of the changes to watch for.
    /// * `recursive` - Whether to watch the directory recursively or not.
    /// # Returns
    /// * A vector of [`FileNotifyInformation`] objects, containing the changes that occurred.
    /// # Notes
    /// * This method is not available when using a single-threaded client.
    /// * This is a long-running operation, and will block until a result is received, or the operation gets cancelled.
    #[cfg(not(feature = "single_threaded"))]
    #[maybe_async]
    pub async fn watch(
        &self,
        filter: NotifyFilter,
        recursive: bool,
    ) -> crate::Result<Vec<FileNotifyInformation>> {
        // First, the client sends a Change Notify Request to the server,
        // and gets a pending response.
        let response = self
            .handle
            .handler
            .send_recvo(
                Content::ChangeNotifyRequest(ChangeNotifyRequest {
                    file_id: self.file_id,
                    flags: NotifyFlags::new().with_watch_tree(recursive),
                    completion_filter: filter,
                    output_buffer_length: 1024,
                }),
                ReceiveOptions {
                    status: &[Status::Pending],
                    cmd: Some(Command::ChangeNotify),
                    ..Default::default()
                },
            )
            .await?;

        if !response.message.header.flags.async_command() {
            return Err(Error::InvalidMessage(
                "Change Notify Request is not async".into(),
            ));
        }

        // Now, we wait for the response to be completed, or cancelled.
        let res = self
            .handler
            .recvo(ReceiveOptions {
                status: &[Status::Success, Status::Cancelled],
                cmd: Some(Command::ChangeNotify),
                msg_id_filter: response.message.header.message_id,
            })
            .await?;

        match res.message.header.status.try_into()? {
            Status::Success => {
                let content = res.message.content.to_changenotifyresponse()?;
                log::debug!("Change Notify Response: {:?}", content);
                Ok(content.buffer)
            }
            Status::Cancelled => {
                log::debug!("Change Notify Response: Cancelled");
                Err(Error::Cancelled)
            }
            _ => panic!("Unexpected status: {:?}", res.message.header.status),
        }
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

#[cfg(feature = "async")]
pub mod iter_stream {
    use super::*;
    use crate::sync_helpers::*;
    use futures_core::Stream;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A stream that allows you to iterate over the contents of a directory.
    /// See [Directory::query_directory] for more information on how to use it.
    pub struct QueryDirectoryStream<'a, T> {
        /// A channel to receive the results from the query.
        /// This is used to send the results from the query loop to the stream.
        receiver: tokio::sync::mpsc::Receiver<crate::Result<T>>,
        /// This is used to wake up the query (against the server) loop when more data is required,
        /// since the iterator is lazy and will not fetch data until it is needed.
        notify_fetch_next: Arc<tokio::sync::Notify>,
        /// Holds the lock while iterating the directory,
        /// to prevent multiple queries at the same time.
        /// See [Directory::query_directory] for more information.
        _lock_guard: MutexGuard<'a, ()>,
    }

    impl<'a, T> QueryDirectoryStream<'a, T>
    where
        T: QueryDirectoryInfoValue,
    {
        pub async fn new(directory: &'a Arc<Directory>, pattern: String) -> crate::Result<Self> {
            let (sender, receiver) = tokio::sync::mpsc::channel(1024);
            let notify_fetch_next = Arc::new(tokio::sync::Notify::new());
            {
                let notify_fetch_next = notify_fetch_next.clone();
                let directory = directory.clone();
                tokio::spawn(async move {
                    Self::fetch_loop(directory, pattern, sender, notify_fetch_next.clone()).await;
                });
            }
            let guard = directory.query_lock.lock().await?;
            Ok(Self {
                receiver,
                notify_fetch_next,
                _lock_guard: guard,
            })
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

                const NO_MORE_FILES: u32 = Status::NoMoreFiles as u32;
                match result {
                    Ok(items) => {
                        for item in items {
                            if sender.send(Ok(item)).await.is_err() {
                                return; // Receiver dropped
                            }
                        }
                    }
                    Err(Error::UnexpectedMessageStatus(NO_MORE_FILES)) => {
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

    impl<'a, T> Stream for QueryDirectoryStream<'a, T>
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
}

#[cfg(not(feature = "async"))]
pub mod iter_sync {
    use super::*;
    use crate::sync_helpers::*;
    pub struct QueryDirectoryIterator<'a, T>
    where
        T: QueryDirectoryInfoValue,
    {
        /// Results from last call to [`Directory::send_query`], that were not yet consumed.
        backlog: Vec<T>,
        /// The directory to query.
        directory: &'a Directory,
        /// The pattern to match against the file names in the directory.
        pattern: String,
        /// Whether this is the first query or not.
        is_first: bool,

        /// The lock being held while iterating the directory.
        _iter_lock_guard: MutexGuard<'a, ()>,
    }

    impl<'a, T> QueryDirectoryIterator<'a, T>
    where
        T: QueryDirectoryInfoValue,
    {
        pub fn new(directory: &'a Directory, pattern: String) -> crate::Result<Self> {
            Ok(Self {
                backlog: Vec::new(),
                directory,
                pattern,
                is_first: true,
                _iter_lock_guard: directory.query_lock.lock()?,
            })
        }
    }

    impl<'a, T> Iterator for QueryDirectoryIterator<'a, T>
    where
        T: QueryDirectoryInfoValue,
    {
        type Item = crate::Result<T>;

        fn next(&mut self) -> Option<Self::Item> {
            // Pop from backlog if we have any results left.
            if !self.backlog.is_empty() {
                return Some(Ok(self.backlog.remove(0)));
            }

            // If we have no backlog, we need to query the directory again.
            let result = self.directory.send_query::<T>(&self.pattern, self.is_first);
            self.is_first = false;
            const NO_MORE_FILES: u32 = Status::NoMoreFiles as u32;
            match result {
                Ok(items) => {
                    if items.is_empty() {
                        None
                    } else {
                        // Store the items in the backlog and return the first one.
                        self.backlog = items;
                        self.next()
                    }
                }
                Err(Error::UnexpectedMessageStatus(NO_MORE_FILES)) => {
                    None // No more files!
                }
                Err(e) => {
                    // Another error occurred, return it.
                    Some(Err(e))
                }
            }
        }
    }
}
