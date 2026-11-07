//! A complete unframed SMB2 NEGOTIATE request represented as structured data.

use super::smb_2_header::Smb2Header;
use super::smb_2_request_body::Smb2RequestBody;

/// Header and body are encoded in sequence before adding Direct TCP framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Request {
    pub header: Smb2Header,
    pub body: Smb2RequestBody,
}
