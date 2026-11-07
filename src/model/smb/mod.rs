//! A complete unframed SMB2 NEGOTIATE request represented as structured data.

mod body;
mod header;

pub use body::Smb2RequestBody;
pub use header::Smb2Header;

/// Header and body are encoded in sequence before adding Direct TCP framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Request {
    pub header: Smb2Header,
    pub body: Smb2RequestBody,
}
