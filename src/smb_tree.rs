use std::{cell::OnceCell, error::Error};

use crate::{
    msg_handler::{OutgoingSMBMessage, SMBHandlerReference, SMBMessageHandler},
    packets::smb2::{
        create::{
            CreateDisposition, ImpersonationLevel, OplockLevel, SMB2CreateContext,
            SMB2CreateRequest, SMB2ShareAccessFlags,
        },
        message::{SMB2Message, SMBMessageContent},
        tree_connect::{SMB2TreeConnectRequest, SMB2TreeDisconnectRequest},
    },
    smb_file::SMBFile,
    smb_session::SMBSessionMessageHandler,
};

type Upstream = SMBHandlerReference<SMBSessionMessageHandler>;

#[derive(Debug)]
struct TreeConnectInfo {
    tree_id: u32,
}

pub struct SMBTree {
    handler: SMBHandlerReference<SMBTreeMessageHandler>,
    name: String,
}

impl SMBTree {
    pub fn new(name: String, upstream: Upstream) -> SMBTree {
        SMBTree {
            handler: SMBTreeMessageHandler::new(upstream),
            name,
        }
    }

    pub fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.handler.borrow().connect_info().is_some() {
            return Err("Tree connection already established!".into());
        }
        // send and receive tree request & response.
        self.handler.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBTreeConnectRequest(SMB2TreeConnectRequest::new(&self.name)),
        )))?;
        let response = self.handler.receive()?;

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
        self.handler
            .borrow_mut()
            .connect_info
            .set(TreeConnectInfo {
                tree_id: response.message.header.tree_id,
            })
            .unwrap();
        Ok(())
    }

    pub fn create(&mut self, file_name: String) -> Result<SMBFile, Box<dyn Error>> {
        let mut result = SMBFile::new(file_name, self.handler.clone());
        result.create()?;
        Ok(result)
    }

    fn disconnect(&mut self) -> Result<(), Box<dyn Error>> {
        if self.handler.borrow_mut().connect_info.get().is_none() {
            return Err("Tree connection not established!".into());
        };

        // send and receive tree disconnect request & response.
        self.handler.send(OutgoingSMBMessage::new(SMB2Message::new(
            SMBMessageContent::SMBTreeDisconnectRequest(SMB2TreeDisconnectRequest::default()),
        )))?;
        let response = self.handler.receive()?;
        if response.message.header.status != 0 {
            return Err("Tree disconnect failed!".into());
        }
        log::info!("Disconnected from tree {}", self.name);
        self.handler.borrow_mut().connect_info.take();
        Ok(())
    }
}

impl Drop for SMBTree {
    fn drop(&mut self) {
        self.disconnect()
            .or_else(|e| {
                log::error!("Failed to disconnect from tree {}: {}", self.name, e);
                Err(e)
            })
            .ok();
    }
}

pub struct SMBTreeMessageHandler {
    upstream: Upstream,
    connect_info: OnceCell<TreeConnectInfo>,
}

impl SMBTreeMessageHandler {
    pub fn new(upstream: Upstream) -> SMBHandlerReference<SMBTreeMessageHandler> {
        SMBHandlerReference::new(SMBTreeMessageHandler {
            upstream,
            connect_info: OnceCell::new(),
        })
    }

    fn connect_info(&self) -> Option<&TreeConnectInfo> {
        self.connect_info.get()
    }
}

impl SMBMessageHandler for SMBTreeMessageHandler {
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
