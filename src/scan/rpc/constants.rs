//! ONC RPC wire values and independent bounds for portmapper identification.

pub(in crate::scan) const MAX_REPLY_BYTES: usize = 4096;
pub(in crate::scan) const MAX_DUMP_ENTRIES: usize = 128;
pub(super) const PORTMAPPER_PORT: u16 = 111;
pub(super) const PORTMAPPER_PROGRAM: u32 = 100000;
pub(super) const PORTMAPPER_VERSION: u32 = 2;
pub(super) const NULL_PROCEDURE: u32 = 0;
pub(super) const DUMP_PROCEDURE: u32 = 4;
pub(super) const RPC_VERSION: u32 = 2;
pub(super) const CALL: u32 = 0;
pub(super) const REPLY: u32 = 1;
pub(super) const MSG_ACCEPTED: u32 = 0;
pub(super) const SUCCESS: u32 = 0;
pub(super) const AUTH_NONE: u32 = 0;
pub(super) const CALL_HEADER_BYTES: usize = 40;
pub(super) const MAX_VERIFIER_BYTES: u32 = 400;
pub(super) const FINAL_FRAGMENT: u32 = 0x8000_0000;
pub(super) const FRAGMENT_LENGTH_MASK: u32 = 0x7fff_ffff;
