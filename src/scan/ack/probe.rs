//! Original ACK probe data and future ownership of reserved/raw socket resources.

use std::net::{SocketAddr, SocketAddrV4};

use socket2::Socket;
use tokio::io::unix::AsyncFd;

use super::constants::TCP_HEADER_BYTES;

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

/// Select the source address, reserve a TCP source port, build the ACK header,
/// and register a nonblocking raw socket. Sending belongs to the scan entry point.
pub(super) fn prepare_probe(_target: SocketAddr) -> Result<PreparedProbe, String> {
    Err("ACK probe preparation is not implemented".into())
}

/// Obtain the sequence and acknowledgment values that will be retained in AckProbe.
pub(super) fn generate_probe_numbers() -> Result<(u32, u32), String> {
    Err("ACK probe number generation is not implemented".into())
}
