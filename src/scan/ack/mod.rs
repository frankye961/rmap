//! ACK header construction and scaffolding for probe I/O and reply classification.
//!
//! This module is not registered with the application or exposed through a CLI flag yet.
//! Header construction is implemented; next complete setup, reply matching and orchestration.
//! The report will also need an `Unfiltered` outcome before ACK scanning is wired.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use socket2::Socket;
use tokio::io::unix::AsyncFd;

use self::constants::TCP_HEADER_BYTES;
use crate::model::ScanResult;

mod constants;
mod packet;
mod probe;
mod reply;

/// Retain exactly the values sent so a response can be correlated with its request.
#[derive(Debug)]
pub(super) struct AckProbe {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
}

/// Keep the source-port reservation and raw socket alive for the whole exchange.
pub(super) struct PreparedProbe {
    pub source_socket: Socket,
    pub probe: AckProbe,
    pub header: [u8; TCP_HEADER_BYTES],
    pub socket: AsyncFd<Socket>,
}

/// Future per-port entry point. Its error placeholder creates no scan observation.
/// Adapt the completed function to the scanner's result contract when wiring ACK.
pub(super) async fn scan_port(
    _target: SocketAddr,
    _timeout: Duration,
) -> Result<ScanResult, String> {
    Err("ACK scanning is not implemented".into())
}
