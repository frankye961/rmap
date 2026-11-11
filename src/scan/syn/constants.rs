//! SYN-specific settings and the shared wire constants used by SYN helpers.

pub(super) use crate::scan::raw_tcp::constants::{
    DATA_OFFSET_NO_OPTIONS, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, TCP_HEADER_BYTES,
};

pub(super) const SYN_WINDOW: u16 = crate::scan::raw_tcp::constants::DEFAULT_TCP_WINDOW;
pub(super) const CLEANUP_TIMEOUT_MS: u64 = 100;
