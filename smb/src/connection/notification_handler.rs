//! Notification messages handler for SMB2.

use std::sync::Arc;
#[cfg(not(feature = "async"))]
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use maybe_async::*;

use crate::{connection::worker::Worker, msg_handler::IncomingMessage, packets::smb2::Content};

use super::worker::WorkerImpl;
#[cfg(feature = "async")]
use crate::sync_helpers::*;

/// A helper struct to handle incoming Server to client notifications.
#[derive(Debug, Default)]
pub struct NotificationHandler {
    #[cfg(feature = "async")]
    cancel: CancellationToken,
    #[cfg(not(feature = "async"))]
    stopped: Arc<AtomicBool>,
}

impl NotificationHandler {
    pub fn start(worker: &Arc<WorkerImpl>) -> crate::Result<NotificationHandler> {
        let handler = Self::default();
        handler.start_notification_handler(worker)?;
        Ok(handler)
    }

    pub fn stop(&self) {
        #[cfg(feature = "async")]
        self.cancel.cancel();
        #[cfg(not(feature = "async"))]
        self.stopped.store(true, Ordering::SeqCst);
        log::info!("Notification handler stopped.");
    }

    #[async_impl]
    fn start_notification_handler(&self, worker: &Arc<WorkerImpl>) -> crate::Result<()> {
        let worker = worker.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        worker.start_notify_channel(tx)?;
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            loop {
                select! {
                    _ = cancel.cancelled() => {
                        log::info!("Notification handler cancelled.");
                        break;
                    }
                    else => {
                        while let Some(msg) = rx.recv().await {
                            Self::on_notification_message(&worker, msg)
                                .await
                                .unwrap_or_else(|e| log::error!("Error handling notification: {:?}", e));
                        }
                    }
                }
            }
            log::info!("Notification handler thread stopped.");
        });
        log::info!("Notification handler started.");
        Ok(())
    }

    #[sync_impl]
    fn start_notification_handler(&self, worker: &Arc<WorkerImpl>) -> crate::Result<()> {
        let worker = worker.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        worker.start_notify_channel(tx)?;
        let stopped_ref = self.stopped.clone();
        std::thread::spawn(move || {
            while !stopped_ref.load(Ordering::SeqCst) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(notification) => {
                        Self::on_notification_message(&worker, notification).unwrap_or_else(|e| {
                            log::error!("Error handling notification: {:?}", e)
                        });
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Timeout, continue waiting for messages
                    }
                }
            }
            log::info!("Notification handler thread stopped.");
        });
        log::info!("Notification handler started.");
        Ok(())
    }

    #[maybe_async]
    async fn on_notification_message(
        worker: &Arc<WorkerImpl>,
        msg: IncomingMessage,
    ) -> crate::Result<()> {
        match &msg.message.content {
            Content::ServerToClientNotification(notification) => {
                log::info!("Received notification: {:?}", notification);
                match &notification.notification {
                    crate::packets::smb2::Notification::NotifySessionClosed(
                        notify_session_closed,
                    ) => {
                        log::info!("Session closed notification: {:?}", notify_session_closed);
                        worker.session_ended(msg.message.header.session_id).await?;
                    }
                }
            }
            Content::OplockBreakNotify(oplock) => {
                log::info!("Received oplock break notification: {:?}", oplock);
            }
            _ => {
                log::warn!("Received unexpected notification: {:?}", msg);
            }
        }
        Ok(())
    }
}
