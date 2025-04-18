use std::net::{SocketAddr, ToSocketAddrs};

pub struct TransportUtils;

impl TransportUtils {
    pub fn parse_socket_address(address: &str) -> crate::Result<SocketAddr> {
        let mut socket_addrs = address
            .to_socket_addrs()
            .map_err(|_| crate::Error::InvalidAddress(address.to_string()))?;
        socket_addrs
            .next()
            .ok_or(crate::Error::InvalidAddress(address.to_string()))
    }

    pub fn get_server_name(address: &str) -> crate::Result<String> {
        let mut parts = address.split(':');
        let server_name = parts
            .next()
            .ok_or(crate::Error::InvalidAddress(address.to_string()))?;
        Ok(server_name.to_string())
    }
}
