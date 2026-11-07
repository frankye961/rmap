//! SMB2 NEGOTIATE body for the initial SMB 2.0.2 and 2.1 dialect offers.

/// Fixed fields followed by variable-length dialect entries when encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2RequestBody {
    /// The fixed body structure size is 36, excluding dialect entries.
    pub structure_size: u16,
    /// Must agree with the number of entries in `dialects`.
    pub dialect_count: u16,
    pub security_mode: u16,
    pub reserved: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    /// Reserved and set to zero when SMB 3.1.1 is not offered.
    pub client_start_time: u64,
    /// Offered protocol revisions, initially 0x0202 and 0x0210.
    pub dialects: Vec<u16>,
}
