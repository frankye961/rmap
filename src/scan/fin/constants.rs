//! Future FIN-specific probe settings.
//!
//! TCP wire values, including FLAG_FIN and header sizes, already belong to
//! crate::scan::raw_tcp::constants and should be reused rather than duplicated.
pub(super) const FIN_WINDOW: u16 = crate::scan::raw_tcp::constants::DEFAULT_TCP_WINDOW;
