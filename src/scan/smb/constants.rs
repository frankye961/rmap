//! Fixed values for the initial unsigned SMB2 NEGOTIATE request.

pub(super) const DIRECT_TCP_PORT: u16 = 445;
pub(super) const PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
pub(super) const HEADER_STRUCTURE_SIZE: u16 = 64;
pub(super) const NEGOTIATE_STRUCTURE_SIZE: u16 = 36;
pub(super) const NEGOTIATE_RESPONSE_STRUCTURE_SIZE: u16 = 65;
// The response's StructureSize value is 65, but its fixed fields occupy 64 bytes.
pub(super) const MIN_NEGOTIATE_RESPONSE_SIZE: usize = HEADER_STRUCTURE_SIZE as usize + 64;

pub(super) const DIALECT_2_0_2: u16 = 0x0202;
pub(super) const DIALECT_2_1: u16 = 0x0210;

// Header values for a single unsigned negotiation before a session or tree exists.
pub(super) const NEGOTIATE_COMMAND: u16 = 0x0000;
pub(super) const NEGOTIATE_CREDIT_CHARGE: u16 = 0;
pub(super) const INITIAL_CREDIT_REQUEST: u16 = 1;
pub(super) const INITIAL_CHANNEL_SEQUENCE: u16 = 0;
pub(super) const REQUEST_FLAGS: u32 = 0;
pub(super) const SERVER_TO_REDIR: u32 = 0x0000_0001;
pub(super) const ASYNC_COMMAND: u32 = 0x0000_0002;
pub(super) const STATUS_SUCCESS: u32 = 0;
pub(super) const NO_NEXT_COMMAND: u32 = 0;
pub(super) const NO_TREE_ID: u32 = 0;
pub(super) const NO_SESSION_ID: u64 = 0;
pub(super) const UNSIGNED_SIGNATURE: [u8; 16] = [0; 16];

// Body values for SMB 2.0.2 and 2.1, without SMB 3.x negotiate contexts.
pub(super) const SIGNING_ENABLED: u16 = 0x0001;
pub(super) const NO_CAPABILITIES: u32 = 0;
pub(super) const RESERVED_CLIENT_START_TIME: u64 = 0;

pub(super) const RESERVED_U16: u16 = 0;
pub(super) const RESERVED_U32: u32 = 0;
pub(super) const MAX_DIRECT_TCP_PAYLOAD: usize = 0x00FF_FFFF;
