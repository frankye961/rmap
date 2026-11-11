//! Shared wire sizes, TCP flags, and IPv4 fragment masks; these follow the protocol.

pub(in crate::scan) const TCP_HEADER_BYTES: usize = 20;
pub(in crate::scan) const MIN_IPV4_HEADER_BYTES: usize = 20;
pub(in crate::scan) const PSEUDO_HEADER_BYTES: usize = 12;
pub(in crate::scan) const MAX_IPV4_PACKET_BYTES: usize = u16::MAX as usize;
pub(in crate::scan) const IP_PROTOCOL_TCP: u8 = 6;
pub(in crate::scan) const DATA_OFFSET_NO_OPTIONS: u8 = ((TCP_HEADER_BYTES / 4) as u8) << 4;
pub(in crate::scan) const FLAG_FIN: u8 = 0x01;
pub(in crate::scan) const FLAG_SYN: u8 = 0x02;
pub(in crate::scan) const FLAG_RST: u8 = 0x04;
pub(in crate::scan) const FLAG_ACK: u8 = 0x10;
pub(in crate::scan) const IPV4_MORE_FRAGMENTS: u16 = 0x2000;
pub(in crate::scan) const IPV4_FRAGMENT_OFFSET: u16 = 0x1fff;

/// Initial advertised window for the current fixed-header probes, in bytes.
pub(in crate::scan) const DEFAULT_TCP_WINDOW: u16 = 1024;
