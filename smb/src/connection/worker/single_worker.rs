use std::{cell::RefCell, sync::Arc, time::Duration};

use crate::{
    connection::transformer::Transformer,
    msg_handler::{IncomingMessage, OutgoingMessage, ReceiveOptions, SendMessageResult},
};

use super::Worker;

/// Single-threaded worker.
#[derive(Debug)]
pub struct SingleWorker {
    // for trait compatibility, we need to use RefCell here,
    // since we can't have mutable references to the same object in multiple threads,
    // which is useful in the async worker.
    netbios_client: RefCell<NetBiosClient>,
    transformer: Transformer,
}

impl Worker for SingleWorker {
    fn start(netbios_client: NetBiosClient, timeout: Duration) -> crate::Result<Arc<Self>> {
        if !netbios_client.can_read() || !netbios_client.can_write() {
            return Err(crate::Error::NotConnected);
        }

        netbios_client.set_read_timeout(timeout)?;
        Ok(Arc::new(Self {
            netbios_client: RefCell::new(netbios_client),
            transformer: Transformer::default(),
        }))
    }

    fn stop(&self) -> crate::Result<()> {
        self.netbios_client.borrow_mut().disconnect();
        Ok(())
    }

    fn send(&self, msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        let msg_id = msg.message.header.message_id;
        let finalize_preauth_hash = msg.finalize_preauth_hash;

        let t = self.transformer.transform_outgoing(msg)?;
        self.netbios_client.borrow_mut().send(t)?;

        let hash = match finalize_preauth_hash {
            true => self.transformer.finalize_preauth_hash()?,
            false => None,
        };

        Ok(SendMessageResult::new(msg_id, hash))
    }

    fn receive_next(&self, options: &ReceiveOptions<'_>) -> crate::Result<IncomingMessage> {
        // Receive next message
        let msg = self
            .netbios_client
            .borrow_mut()
            .receive_bytes()
            .map_err(|e| match e {
                crate::Error::IoError(ioe) => {
                    if ioe.kind() == std::io::ErrorKind::WouldBlock {
                        crate::Error::OperationTimeout(
                            "Receive next message".into(),
                            self.netbios_client
                                .borrow()
                                .read_timeout()
                                .unwrap_or(None)
                                .unwrap_or(Duration::ZERO),
                        )
                    } else {
                        crate::Error::IoError(ioe)
                    }
                }
                _ => e,
            })?;
        // Transform the message
        let im = self.transformer.transform_incoming(msg)?;
        // Make sure this is our message.
        // In async clients, this is no issue, but here, we can't deal with unordered/unexpected message IDs.
        if im.message.header.message_id != options.msg_id {
            return Err(crate::Error::UnexpectedMessageId(
                im.message.header.message_id,
                options.msg_id,
            ));
        }
        Ok(im)
    }

    fn transformer(&self) -> &Transformer {
        &self.transformer
    }

    fn set_timeout(&self, timeout: Duration) -> crate::Result<()> {
        self.netbios_client.borrow_mut().set_read_timeout(timeout)
    }
}
