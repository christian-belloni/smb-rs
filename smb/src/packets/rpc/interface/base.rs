use crate::packets::rpc::pdu::DceRpcSyntaxId;
use binrw::prelude::*;

pub trait RpcInterface<T>
where
    T: BoundRpcConnection,
{
    fn syntax_id() -> DceRpcSyntaxId;
    fn new(bound_pipe: T) -> Self;
}

pub trait RpcStubInput: for<'a> BinWrite<Args<'a> = ()> {
    fn serialize(&self) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(vec![]);
        self.write_le(&mut cursor).unwrap();
        cursor.into_inner()
    }
}
pub trait RpcStubOutput: for<'b> BinRead<Args<'b> = ()> {
    fn deserialize(data: &[u8]) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mut cursor = std::io::Cursor::new(data);
        Self::read_le(&mut cursor).map_err(|e| crate::Error::from(e))
    }
}

pub trait BoundRpcConnection {
    fn send_receive<S, R>(&mut self, stub_input: S) -> crate::Result<R>
    where
        S: RpcStubInput,
        R: RpcStubOutput,
    {
        let serialized_input = stub_input.serialize();
        let response = self.send_receive_raw(&serialized_input)?;
        R::deserialize(&response)
    }

    fn send_receive_raw(&mut self, stub_input: &[u8]) -> crate::Result<Vec<u8>>;
}
