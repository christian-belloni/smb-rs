use std::{
    ops::{Deref, DerefMut},
    str::FromStr,
};

use super::ResourceHandle;
use crate::packets::{
    guid::Guid,
    rpc::pdu::*,
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
        let tranfer_syntaxes: [DceRpcSyntaxId; 2] = [
            DceRpcSyntaxId {
                uuid: Guid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(), // NDR64
                version: 1,
            },
            DceRpcSyntaxId {
                uuid: Guid::from_str("6cb71c2c-9812-4540-0300-000000000000").unwrap(),
                version: 2,
            },
        ];
        let context_elements = Self::make_bind_contexts(syntax_id.clone(), &tranfer_syntaxes);

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
                context_elements,
            }
            .into(),
        )
        .await?;

        let bind_ack = match bind_ack.content() {
            DcRpcCoPktResponseContent::BindAck(bind_ack) => {
                log::debug!("Bounded to pipe with port spec {}", bind_ack.port_spec);
                bind_ack
            }
            _ => {
                return Err(crate::Error::InvalidMessage(format!(
                    "Expected BindAck, got: {:?}",
                    bind_ack
                )));
            }
        };

        Self::check_bind_results(&bind_ack, &tranfer_syntaxes)?;

        Ok(BoundRpcPipe {
            pipe,
            syntax_id,
            next_call_id: START_CALL_ID + 1,
        })
    }

    fn make_bind_contexts(
        syntax_id: DceRpcSyntaxId,
        transfer_syntaxes: &[DceRpcSyntaxId],
    ) -> Vec<DcRpcCoPktBindContextElement> {
        let mut result = vec![];

        for (i, syntax) in transfer_syntaxes.into_iter().enumerate() {
            result.push(DcRpcCoPktBindContextElement {
                context_id: i as u16,
                abstract_syntax: syntax_id.clone(),
                transfer_syntaxes: vec![syntax.clone()],
            });
        }

        result
    }

    fn check_bind_results(
        bind_ack: &DcRpcCoPktBindAck,
        transfer_syntaxes: &[DceRpcSyntaxId],
    ) -> crate::Result<()> {
        const BIND_TIME_FEATURE_NEG_PREFIX: &str = "6cb71c2c-9812-4540-";
        if bind_ack.results.len() != transfer_syntaxes.len() {
            return Err(crate::Error::InvalidMessage(format!(
                "BindAck results length {} does not match transfer syntaxes length {}",
                bind_ack.results.len(),
                transfer_syntaxes.len()
            )));
        }
        for (ack_context, syntax) in bind_ack.results.iter().zip(transfer_syntaxes) {
            if syntax
                .uuid
                .to_string()
                .starts_with(BIND_TIME_FEATURE_NEG_PREFIX)
            {
                // Bind time feature negotiation element. Currently ignored.
                log::debug!(
                    "Bind time feature negotiation flags: {:?}",
                    ack_context.result as u16
                );
                continue;
            }
            if ack_context.result != DceRpcCoPktBindAckDefResult::Acceptance {
                return Err(crate::Error::InvalidMessage(format!(
                    "BindAck result for syntax {} was not acceptance: {:?}",
                    syntax, ack_context
                )));
            }
            if &ack_context.syntax != syntax {
                return Err(crate::Error::InvalidMessage(format!(
                    "BindAck abstract syntax {} does not match expected {}",
                    ack_context.syntax, syntax
                )));
            }
        }

        Ok(())
    }

    #[maybe_async]
    async fn rpc_send_recv(
        pipe: &mut Pipe,
        call_id: u32,
        to_send: DcRpcCoPktRequestContent,
    ) -> crate::Result<DceRpcCoResponsePkt> {
        const PACKED_DREP: u32 = 0x10;

        const READ_WRITE_PIPE_OFFSET: u64 = 0;
        let dcerpc_request_buffer: Vec<u8> = DceRpcCoRequestPkt::new(
            to_send,
            call_id,
            DceRpcCoPktFlags::new()
                .with_first_frag(true)
                .with_last_frag(true),
            PACKED_DREP,
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

        if response.packed_drep() != PACKED_DREP {
            return Err(crate::Error::InvalidMessage(format!(
                "Currently Unsupported packed DREP: {}",
                response.packed_drep()
            )));
        }

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
