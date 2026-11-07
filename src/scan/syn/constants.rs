//! IPv4/TCP wire constants and limits for the current SYN implementation.

pub(super) const TCP_HEADER_BYTES: usize = 20;
pub(super) const MIN_IPV4_HEADER_BYTES: usize = 20;
pub(super) const PSEUDO_HEADER_BYTES: usize = 12;
pub(super) const MAX_IPV4_PACKET_BYTES: usize = u16::MAX as usize;
pub(super) const IP_PROTOCOL_TCP: u8 = 6;
pub(super) const DATA_OFFSET_NO_OPTIONS: u8 = ((TCP_HEADER_BYTES / 4) as u8) << 4;
pub(super) const FLAG_FIN: u8 = 0x01;
pub(super) const FLAG_SYN: u8 = 0x02;
pub(super) const FLAG_RST: u8 = 0x04;
pub(super) const FLAG_ACK: u8 = 0x10;
pub(super) const IPV4_MORE_FRAGMENTS: u16 = 0x2000;
pub(super) const IPV4_FRAGMENT_OFFSET: u16 = 0x1fff;
pub(super) const SYN_WINDOW: u16 = 1024;
pub(super) const CLEANUP_TIMEOUT_MS: u64 = 100;
