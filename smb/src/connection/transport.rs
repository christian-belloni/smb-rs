use std::time::Duration;

use super::TransportConfig;

pub mod quic;
pub mod tcp;
pub mod traits;
pub mod utils;

pub use traits::*;

pub fn make_transport(
    transport: &TransportConfig,
    timeout: Duration,
) -> crate::Result<Box<dyn SmbTransport>> {
    match transport {
        TransportConfig::Tcp => Ok(Box::new(tcp::TcpTransport::new(timeout))),
        TransportConfig::Quic(quic_config) => Ok(Box::new(quic::QuicTransport::new(quic_config)?)),
    }
}
