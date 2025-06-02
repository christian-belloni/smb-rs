use std::ops::{Deref, DerefMut};

use super::ResourceHandle;
use crate::packets::{
    dcerpc::*,
    smb2::{ReadRequest, WriteRequest},
};
use maybe_async::*;
pub struct Pipe {
    handle: ResourceHandle,
}

impl Pipe {
    pub fn new(handle: ResourceHandle) -> Self {
        Pipe { handle }
    }

    pub fn handle(&self) -> &ResourceHandle {
        &self.handle
    }

    #[maybe_async]
    pub async fn bind(self, syntax_id: DceRpcSyntaxId) -> crate::Result<BoundRpcPipe> {
        BoundRpcPipe::bind(self, syntax_id).await
    }
}

pub struct BoundRpcPipe {
    pipe: Pipe,
    syntax_id: DceRpcSyntaxId,
    next_call_id: u32,
}

impl BoundRpcPipe {
    #[maybe_async]
    pub async fn bind(mut pipe: Pipe, syntax_id: DceRpcSyntaxId) -> crate::Result<Self> {
        const START_CALL_ID: u32 = 2;
        const DEFAULT_FRAG_LIMIT: u16 = 4280;
        const NO_ASSOC_GROUP_ID: u32 = 0;
        let bind_ack = Self::rpc_send_recv(
            &mut pipe,
            START_CALL_ID,
            DcRpcCoPktBind {
                max_xmit_frag: DEFAULT_FRAG_LIMIT,
                max_recv_frag: DEFAULT_FRAG_LIMIT,
                assoc_group_id: NO_ASSOC_GROUP_ID,
                context_elements: vec![],
            }
            .into(),
        )
        .await?;

        match bind_ack.content() {
            DcRpcCoPktResponseContent::BindAck(bind_ack) => {
                log::debug!("Bounded to pipe with port spec {}", bind_ack.port_spec);
            }
            _ => {
                return Err(crate::Error::InvalidMessage(format!(
                    "Expected BindAck, got: {:?}",
                    bind_ack
                )));
            }
        }

        Ok(BoundRpcPipe {
            pipe,
            syntax_id,
            next_call_id: START_CALL_ID + 1,
        })
    }

    #[maybe_async]
    async fn rpc_send_recv(
        pipe: &mut Pipe,
        call_id: u32,
        to_send: DcRpcCoPktRequestContent,
    ) -> crate::Result<DceRpcCoResponsePkt> {
        const READ_WRITE_PIPE_OFFSET: u64 = 0;
        let dcerpc_request_buffer: Vec<u8> = DceRpcCoRequestPkt::new(
            to_send,
            call_id,
            DceRpcCoPktFlags::new()
                .with_first_frag(true)
                .with_last_frag(true),
            0x00000010,
        )
        .try_into()?;
        let exp_write_size = dcerpc_request_buffer.len() as u32;
        let write_result = pipe
            .send_receive(
                WriteRequest {
                    offset: READ_WRITE_PIPE_OFFSET,
                    file_id: pipe.handle.file_id,
                    flags: Default::default(),
                    buffer: dcerpc_request_buffer,
                }
                .into(),
            )
            .await?;
        if write_result.message.content.to_write()?.count != exp_write_size {
            return Err(crate::Error::InvalidMessage(
                "Failed to write the full request to the pipe".to_string(),
            ));
        }

        let read_result = pipe
            .send_receive(
                ReadRequest {
                    flags: Default::default(),
                    length: 1024,
                    offset: READ_WRITE_PIPE_OFFSET,
                    file_id: pipe.handle.file_id,
                    minimum_count: DceRpcCoRequestPkt::COMMON_SIZE_BYTES as u32,
                }
                .into(),
            )
            .await?;
        let content = read_result.message.content.to_read()?;
        let response = DceRpcCoResponsePkt::try_from(content.buffer.as_ref())?;
        Ok(response)
    }

    pub fn pipe(&self) -> &Pipe {
        &self.pipe
    }
}

impl Deref for Pipe {
    type Target = ResourceHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for Pipe {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}
