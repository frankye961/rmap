//! Fields of the synchronous SMB2 request header, separate from wire encoding.

/// A request header; numeric fields must be encoded explicitly as little-endian bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Header {
    pub protocol_id: [u8; 4],
    pub structure_size: u16,
    pub credit_charge: u16,
    pub channel_sequence: u16,
    pub reserved: u16,
    pub command: u16,
    pub credit_request: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub reserved2: u32,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}
