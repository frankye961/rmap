//! Constants for a bare IPv4 TCP ACK probe, sharing wire values with SYN.

pub(super) use crate::scan::raw_tcp::constants::{
    DATA_OFFSET_NO_OPTIONS, FLAG_ACK, FLAG_RST, IP_PROTOCOL_TCP, IPV4_FRAGMENT_OFFSET,
    IPV4_MORE_FRAGMENTS, MAX_IPV4_PACKET_BYTES, MIN_IPV4_HEADER_BYTES, PSEUDO_HEADER_BYTES,
    TCP_HEADER_BYTES,
};

/// Probe setting, not a requirement imposed by the TCP specification.
pub(super) const ACK_WINDOW: u16 = crate::scan::raw_tcp::constants::DEFAULT_TCP_WINDOW;
