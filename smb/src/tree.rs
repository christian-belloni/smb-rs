use std::sync::Arc;

use maybe_async::*;

use crate::connection::connection_info::ConnectionInfo;
use crate::sync_helpers::*;

use crate::{
    msg_handler::{HandlerReference, MessageHandler},
    packets::{
        fscc::FileAccessMask,
        smb2::{
            create::CreateDisposition,
            plain::Content,
            tree_connect::{TreeConnectRequest, TreeDisconnectRequest},
        },
    },
    resource::Resource,
    session::SessionMessageHandler,
    Error,
};

type Upstream = HandlerReference<SessionMessageHandler>;

#[derive(Debug)]
struct TreeConnectInfo {
    tree_id: u32,
}

pub struct Tree {
    handler: HandlerReference<TreeMessageHandler>,
    name: String,
    conn_info: Arc<ConnectionInfo>,
}

impl Tree {
    #[maybe_async]
    pub async fn connect(
        name: &str,
        upstream: Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Tree> {
        let mut t = Tree {
            handler: TreeMessageHandler::new(upstream, name.to_string()),
            name: name.to_string(),
            conn_info: conn_info.clone(),
        };
        t.server_connect().await?;
        Ok(t)
    }

    #[maybe_async]
    async fn server_connect(&mut self) -> crate::Result<()> {
        if self.handler.connect_info.read().await?.is_some() {
            return Err(Error::InvalidState(
                "Tree connection already established!".into(),
            ));
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

        // Make sure the share flags from the server are valid to the dialect.
        if ((!u32::from_le_bytes(
            self.conn_info
                .dialect
                .get_tree_connect_caps_mask()
                .into_bytes(),
        )) & u32::from_le_bytes(_response_content.capabilities.into_bytes()))
            != 0
        {
            return Err(Error::InvalidMessage(format!(
                "Invalid share flags received from server for tree '{}': {:?}",
                self.name, _response_content.share_flags
            )));
        }

        // Same for share flags
        if ((!u32::from_le_bytes(self.conn_info.dialect.get_share_flags_mask().into_bytes()))
            & u32::from_le_bytes(_response_content.share_flags.into_bytes()))
            != 0
        {
            return Err(Error::InvalidMessage(format!(
                "Invalid capabilities received from server for tree '{}': {:?}",
                self.name, _response_content.capabilities
            )));
        }

        log::info!(
            "Connected to tree {} (#{})",
            self.name,
            response.message.header.tree_id
        );
        *self.handler.connect_info.write().await? = Some(TreeConnectInfo {
            tree_id: response.message.header.tree_id,
        });
        Ok(())
    }

    /// Connects to a resource (file, directory, etc.) on the remote server by it's name.
    #[maybe_async]
    pub async fn create(
        &mut self,
        file_name: &str,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        Ok(Resource::create(
            file_name,
            self.handler.clone(),
            disposition,
            desired_access,
            &self.conn_info,
        )
        .await?)
    }
}

pub struct TreeMessageHandler {
    upstream: Upstream,
    connect_info: RwLock<Option<TreeConnectInfo>>,
    tree_name: String,
}

impl TreeMessageHandler {
    pub fn new(upstream: Upstream, tree_name: String) -> HandlerReference<TreeMessageHandler> {
        HandlerReference::new(TreeMessageHandler {
            upstream,
            connect_info: RwLock::new(None),
            tree_name,
        })
    }

    #[maybe_async]
    async fn disconnect(&mut self) -> crate::Result<()> {
        let connected = { self.connect_info.read().await?.is_some() };

        if !connected {
            return Err(Error::InvalidState(
                "Tree connection already disconnected!".into(),
            ));
        }

        log::debug!("Disconnecting from tree {}", self.tree_name);

        // send and receive tree disconnect request & response.
        let _response = self
            .send_recv(Content::TreeDisconnectRequest(
                TreeDisconnectRequest::default(),
            ))
            .await?;

        self.connect_info.write().await?.take();

        log::info!("Disconnected from tree {}", self.tree_name);

        Ok(())
    }

    #[cfg(feature = "async")]
    #[inline]
    pub async fn disconnect_async(&mut self) {
        self.disconnect()
            .await
            .or_else(|e| {
                log::error!("Failed to disconnect from tree: {}", e);
                Err(e)
            })
            .ok();
    }
}

impl MessageHandler for TreeMessageHandler {
    #[maybe_async]
    async fn sendo(
        &self,
        mut msg: crate::msg_handler::OutgoingMessage,
    ) -> crate::Result<crate::msg_handler::SendMessageResult> {
        msg.message.header.tree_id = match self.connect_info.read().await?.as_ref() {
            Some(info) => info.tree_id,
            None => 0,
        };
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.upstream.recvo(options).await
    }
}

#[cfg(feature = "sync")]
impl Drop for TreeMessageHandler {
    fn drop(&mut self) {
        self.disconnect()
            .or_else(|e| {
                log::error!("Failed to disconnect from tree {}: {}", self.tree_name, e);
                Err(e)
            })
            .ok();
    }
}

#[cfg(feature = "async")]
impl Drop for TreeMessageHandler {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.disconnect_async().await;
            })
        })
    }
}
