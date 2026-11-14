//! Shared, already implemented IPv4/TCP mechanics for raw scan methods.

pub(in crate::scan) mod checksum;
pub(in crate::scan) mod constants;
pub(in crate::scan) mod packet;
pub(in crate::scan) mod socket;
