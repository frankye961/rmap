//! Constants for a bare IPv4 TCP ACK probe, sharing wire values with SYN.

pub(super) use crate::scan::raw_tcp::constants::{
    DATA_OFFSET_NO_OPTIONS, FLAG_ACK, FLAG_RST, TCP_HEADER_BYTES,
};

/// Probe setting, not a requirement imposed by the TCP specification.
pub(super) const ACK_WINDOW: u16 = crate::scan::raw_tcp::constants::DEFAULT_TCP_WINDOW;
