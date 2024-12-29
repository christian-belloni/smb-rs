use std::{cell::OnceCell, error::Error};

use crate::{
    msg_handler::{OutgoingSMBMessage, SMBHandlerReference, SMBMessageHandler},
    packets::smb2::{
        message::{SMB2Message, SMBMessageContent},
        tree_connect::{SMB2TreeConnectRequest, SMB2TreeDisconnectRequest},
    },
    smb_session::SMBSessionMessageHandler,
};

type Upstream = SMBHandlerReference<SMBSessionMessageHandler>;

#[derive(Debug)]
struct TreeConnectInfo {
    tree_id: u32
}

pub struct SMBTree {
    upstream: Upstream,
    name: String,
    connect_info: OnceCell<TreeConnectInfo>,
}

impl SMBTree {
    pub fn new(name: String, upstream: Upstream) -> SMBTree {
        SMBTree {
            upstream,
            name,
            connect_info: OnceCell::new(),
        }
    }

    pub fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.connect_info.get().is_some() {
            return Err("Tree connection already established!".into());
        }
        // send and receive tree request & response.
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBTreeConnectRequest(SMB2TreeConnectRequest::new(&self.name)),
        )))?;
        let response = self.receive()?;

        let _response_content = match response.message.content {
            SMBMessageContent::SMBTreeConnectResponse(response) => Some(response),
            _ => None,
        }
        .unwrap();
        log::info!(
            "Connected to tree {} (@{})",
            self.name,
            response.message.header.tree_id
        );
        self.connect_info.set(TreeConnectInfo {
            tree_id: response.message.header.tree_id,
        }).unwrap();
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.connect_info.get().is_none() {
            return Err("Tree connection not established!".into());
        };

        // send and receive tree disconnect request & response.
        self.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBTreeDisconnectRequest(SMB2TreeDisconnectRequest::default()),
        )))?;
        let response = self.receive()?;
        if response.message.header.status != 0 {
            return Err("Tree disconnect failed!".into());
        }
        log::info!("Disconnected from tree {}", self.name);
        self.connect_info.take();
        Ok(())
    }
}

impl SMBMessageHandler for SMBTree {
    fn send(
        &mut self,
        mut msg: crate::msg_handler::OutgoingSMBMessage,
    ) -> Result<crate::msg_handler::SendMessageResult, Box<dyn std::error::Error>> {
        msg.message.header.tree_id = match self.connect_info.get() {
            Some(info) => info.tree_id,
            None => 0,
        };
        self.upstream.borrow_mut().send(msg)
    }

    fn receive(
        &mut self,
    ) -> Result<crate::msg_handler::IncomingSMBMessage, Box<dyn std::error::Error>> {
        self.upstream.borrow_mut().receive()
    }
}

impl Drop for SMBTree {
    fn drop(&mut self) {
        self.disconnect().or_else(|e| {
            log::error!("Failed to disconnect from tree {}: {}", self.name, e);
            Err(e)
        }).ok();
    }
}
