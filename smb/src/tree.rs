use maybe_async::*;
use std::error::Error;

#[cfg(feature = "async")]
use tokio::sync::OnceCell;
#[cfg(not(feature = "async"))]
use std::cell::OnceCell;

use crate::{
    msg_handler::{HandlerReference, MessageHandler},
    packets::smb2::{
        create::CreateDisposition,
        fscc::FileAccessMask,
        plain::Content,
        tree_connect::{TreeConnectRequest, TreeDisconnectRequest},
    },
    resource::Resource,
    session::SessionMessageHandler,
};

type Upstream = HandlerReference<SessionMessageHandler>;

#[derive(Debug)]
struct TreeConnectInfo {
    tree_id: u32,
}

pub struct Tree {
    handler: HandlerReference<TreeMessageHandler>,
    name: String,
}

impl Tree {
    pub fn new(name: String, upstream: Upstream) -> Tree {
        Tree {
            handler: TreeMessageHandler::new(upstream),
            name,
        }
    }

    #[maybe_async]
    pub async fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.handler.connect_info().is_some() {
            return Err("Tree connection already established!".into());
        }
        // send and receive tree request & response.
        let response = self
            .handler
            .send_recv(Content::TreeConnectRequest(TreeConnectRequest::new(
                &self.name,
            )))
            .await?;

        let _response_content = match response.message.content {
            Content::TreeConnectResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();
        log::info!(
            "Connected to tree {} (#{})",
            self.name,
            response.message.header.tree_id
        );
        self.handler
            .connect_info
            .set(TreeConnectInfo {
                tree_id: response.message.header.tree_id,
            })
            .unwrap();
        Ok(())
    }

    /// Connects to a resource (file, directory, etc.) on the remote server by it's name.
    #[maybe_async]
    pub async fn create(
        &mut self,
        file_name: String,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> Result<Resource, Box<dyn Error>> {
        Ok(Resource::create(file_name, self.handler.clone(), disposition, desired_access).await?)
    }

    #[maybe_async]
    async fn disconnect(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Disconnecting from tree {}", self.name);

        if !self.handler.connect_info.initialized() {
            // No tree connection to disconnect from.
            return Ok(());
        };

        // send and receive tree disconnect request & response.
        let _response = self
            .handler
            .send_recv(Content::TreeDisconnectRequest(
                TreeDisconnectRequest::default(),
            ))
            .await?;

        log::info!("Disconnected from tree {}", self.name);
        self.handler.connect_info.take();
        Ok(())
    }

    #[cfg(feature = "async")]
    #[inline]
    pub async fn disconnect_async(&mut self) {
        self.disconnect()
            .await
            .or_else(|e| {
                log::error!("Failed to disconnect from tree {}: {}", self.name, e);
                Err(e)
            })
            .ok();
    }
}

#[cfg(not(feature = "async"))]
impl Drop for Tree {
    fn drop(&mut self) {
        self.disconnect()
            .or_else(|e| {
                log::error!("Failed to disconnect from tree {}: {}", self.name, e);
                Err(e)
            })
            .ok();
    }
}

#[cfg(feature = "async")]
impl Drop for Tree {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.disconnect_async().await;
            })
        })
    }
}

pub struct TreeMessageHandler {
    upstream: Upstream,
    connect_info: OnceCell<TreeConnectInfo>,
}

impl TreeMessageHandler {
    pub fn new(upstream: Upstream) -> HandlerReference<TreeMessageHandler> {
        HandlerReference::new(TreeMessageHandler {
            upstream,
            connect_info: OnceCell::new(),
        })
    }

    fn connect_info(&self) -> Option<&TreeConnectInfo> {
        self.connect_info.get()
    }
}

impl MessageHandler for TreeMessageHandler {
    #[maybe_async]
    async fn hsendo(
        &self,
        mut msg: crate::msg_handler::OutgoingMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        msg.message.header.tree_id = match self.connect_info.get() {
            Some(info) => info.tree_id,
            None => 0,
        };
        self.upstream.hsendo(msg).await
    }

    #[maybe_async]
    async fn hrecvo(
        &self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> Result<crate::msg_handler::IncomingMessage, Box<dyn std::error::Error>> {
        self.upstream.hrecvo(options).await
    }
}
