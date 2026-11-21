//! Scaffolding for TCP FIN scanning within the existing scanner.
//!
//! This module is compiled, but has no scan implementation or CLI option yet.
//! Reuse shared raw_tcp mechanics when adding packet construction and probe I/O.

use crate::scan::raw_tcp::constants::TCP_HEADER_BYTES;
use socket2::Socket;
use std::net::SocketAddrV4;
use tokio::io::unix::AsyncFd;

mod constants;
mod packet;
mod probe;
mod reply;

pub(super) struct FinProbe {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    pub sequence_number: u32,
}

/// Keep the source-port reservation and raw socket alive for the whole exchange.
pub(super) struct PreparedProbe {
    pub _source_socket: Socket,
    pub probe: FinProbe,
    pub header: [u8; TCP_HEADER_BYTES],
    pub socket: AsyncFd<Socket>,
}
