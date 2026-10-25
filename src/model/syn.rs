//! Data passed between SYN packet parsing, reply matching, and cleanup.

use std::net::{Ipv4Addr, SocketAddrV4};

/// Validated IPv4 addresses and the TCP segment borrowed from received bytes.
#[derive(Debug)]
pub struct ParsedIpv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub tcp_segment: &'a [u8],
}

/// TCP fields extracted after header-length and checksum validation.
#[derive(Debug)]
pub struct TcpReply {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub flags: u8,
}

/// Original probe values retained for response matching and reset construction.
#[derive(Debug)]
pub struct SynProbe {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    pub sequence_number: u32,
}
