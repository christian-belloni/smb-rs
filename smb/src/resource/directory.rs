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
    pub fn new(handle: ResourceHandle) -> Self {
        let access: DirAccessMask = handle.access.into();
        Directory {
            handle,
            access,
            query_lock: Default::default(),
        }
    }

    /// An internal method that performs a query on the directory.
    /// # Arguments
    /// * `pattern` - The pattern to match against the file names in the directory. Use wildcards like `*` and `?` to match multiple files.
    /// * `restart` - Whether to restart the scan or not. This is used to indicate whether this is the first query or not.
    /// # Returns
    /// * A vector of [`QueryDirectoryInfoValue`] objects, containing the results of the query.
    /// * If the query returned [`Status::NoMoreFiles`], an empty vector is returned.
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
            .send_receive(
                QueryDirectoryRequest {
                    file_information_class: T::CLASS_ID,
                    flags: QueryDirectoryFlags::new().with_restart_scans(restart),
                    file_index: 0,
                    file_id: self.handle.file_id,
                    output_buffer_length: 0x1000,
                    file_name: pattern.into(),
                }
                .into(),
            )
            .await;

        const STATUS_NO_MORE_FILES: u32 = Status::NoMoreFiles as u32;
        let response = match response {
            Ok(res) => res,
            Err(Error::UnexpectedMessageStatus(STATUS_NO_MORE_FILES)) => {
                log::debug!("No more files in directory");
                return Ok(vec![]);
            }
            Err(e) => {
                log::error!("Error querying directory: {}", e);
                return Err(e);
            }
        };

        Ok(response
            .message
            .content
            .to_querydirectory()?
            .read_output()?)
    }

    /// Asynchronously iterates over the directory contents, using the provided pattern and information type.
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

    /// Synchronously iterates over the directory contents, using the provided pattern and information type.
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
    /// * This is a long-running operation, and will block until a result is received, or the operation gets cancelled.
    #[maybe_async]
    pub async fn watch(
        &self,
        filter: NotifyFilter,
        recursive: bool,
    ) -> crate::Result<Vec<FileNotifyInformation>> {
        let response = self
            .handle
            .handler
            .send_recvo(
                ChangeNotifyRequest {
                    file_id: self.file_id,
                    flags: NotifyFlags::new().with_watch_tree(recursive),
                    completion_filter: filter,
                    output_buffer_length: 1024,
                }
                .into(),
                ReceiveOptions {
                    allow_async: true,
                    cmd: Some(Command::ChangeNotify),
                    ..Default::default()
                },
            )
            .await;

        let response = match response {
            Ok(res) => res,
            // Handle `Status::NotifyCleanup` as a special case
            Err(Error::UnexpectedMessageStatus(c)) => {
                let status = match Status::try_from(c) {
                    Ok(status) => status,
                    _ => return Err(Error::UnexpectedMessageStatus(c)),
                };
                if status == Status::NotifyCleanup {
                    log::info!("Notify cleanup, no more notifications");
                    return Ok(vec![]);
                } else {
                    log::error!(
                        "Error watching directory: {}",
                        Error::UnexpectedMessageStatus(c)
                    );
                    return Err(Error::UnexpectedMessageStatus(c));
                }
            }
            Err(e) => {
                log::error!("Error watching directory: {}", e);
                return Err(e);
            }
        };

        Ok(response.message.content.to_changenotify()?.buffer)
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

                match result {
                    Ok(items) => {
                        if items.is_empty() {
                            // No more files, exit the loop
                            break;
                        }
                        for item in items {
                            if sender.send(Ok(item)).await.is_err() {
                                return; // Receiver dropped
                            }
                        }
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
            let query_result = self.directory.send_query::<T>(&self.pattern, self.is_first);
            self.is_first = false;
            match query_result {
                Ok(next_backlog) => {
                    if next_backlog.is_empty() {
                        // No more items
                        None
                    } else {
                        // Store the items in the backlog and return the first one.
                        self.backlog = next_backlog;
                        self.next()
                    }
                }
                Err(e) => {
                    // Another error occurred, return it.
                    Some(Err(e))
                }
            }
        }
    }
}
