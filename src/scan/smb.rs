//! Learning scaffold for SMB2 negotiation over Direct TCP on port 445.
//! Compiled in test builds only; not connected to the TCP scanner yet.

use std::net::SocketAddr;

use tokio::io::AsyncRead;
use tokio::time::Instant;

use crate::model::service_information::ServiceInformation;
use crate::model::smb_2_header::Smb2Header;
use crate::model::smb_2_request::Smb2Request;
use crate::model::smb_2_request_body::Smb2RequestBody;

mod constants;

/// Select an initial candidate port; only a validated response identifies SMB.
pub(super) fn is_smb_candidate(_port: u16) -> bool {
    _port == constants::DIRECT_TCP_PORT
}

/// Assemble a structured SMB2 NEGOTIATE request offering dialects 2.0.2 and 2.1.
/// Byte encoding and Direct TCP framing are separate steps.
pub(super) fn build_smb_negotiate_request(
    _message_id: u64,
    _client_guid: [u8; 16],
) -> Result<Smb2Request, String> {
    let _dialects: Vec<u16> = vec![constants::DIALECT_2_0_2, constants::DIALECT_2_1];
    let _request_body = build_smb2_negotiate_request_body(&_dialects, _client_guid)?;
    let _header = build_smb2_negotiate_request_header(_message_id)?;
    Ok(Smb2Request {
        header: _header,
        body: _request_body,
    })
}

/// Prepare the fixed body fields, client GUID, and offered dialects as structured data.
/// Byte encoding is a separate step.
fn build_smb2_negotiate_request_body(
    _dialects: &[u16],
    _client_guid: [u8; 16],
) -> Result<Smb2RequestBody, String> {
    if _dialects.len() > u16::MAX as usize || _dialects.is_empty() {
        return Err("Too many dialects for SMB2 NEGOTIATE request".into());
    }
    let _request_body = Smb2RequestBody {
        structure_size: constants::NEGOTIATE_STRUCTURE_SIZE,
        dialect_count: _dialects.len() as u16,
        security_mode: constants::SIGNING_ENABLED,
        reserved: constants::RESERVED_U16,
        capabilities: constants::NO_CAPABILITIES,
        client_guid: _client_guid,
        client_start_time: constants::RESERVED_CLIENT_START_TIME,
        dialects: _dialects.to_vec(),
    };
    Ok(_request_body)
}

/// Prepare the synchronous NEGOTIATE header fields, retaining the caller's message ID.
/// Encoding the header and assembling wire bytes are separate steps.
fn build_smb2_negotiate_request_header(_message_id: u64) -> Result<Smb2Header, String> {
    let _header = Smb2Header {
        protocol_id: constants::PROTOCOL_ID,
        structure_size: constants::HEADER_STRUCTURE_SIZE,
        credit_charge: constants::NEGOTIATE_CREDIT_CHARGE,
        channel_sequence: constants::INITIAL_CHANNEL_SEQUENCE,
        reserved: constants::RESERVED_U16,
        command: constants::NEGOTIATE_COMMAND,
        credit_request: constants::INITIAL_CREDIT_REQUEST,
        flags: constants::REQUEST_FLAGS,
        next_command: constants::NO_NEXT_COMMAND,
        message_id: _message_id,
        reserved2: constants::RESERVED_U32,
        tree_id: constants::NO_TREE_ID,
        session_id: constants::NO_SESSION_ID,
        signature: constants::UNSIGNED_SIGNATURE,
    };
    Ok(_header)
}

/// Prefix a message with a zero byte and its three-byte network-order length.
/// Reject lengths outside the Direct TCP header's 24-bit range.
pub(super) fn frame_smb_message(_message: &[u8]) -> Result<Vec<u8>, String> {
    Err("SMB Direct TCP framing is not implemented".into())
}

/// Connect, send one framed request, and read one reply within the supplied bounds.
/// Connection, writing, and reading must share the caller's absolute deadline.
pub(super) async fn probe(
    _target: SocketAddr,
    _message_id: u64,
    _client_guid: [u8; 16],
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    Err("SMB negotiation exchange is not implemented".into())
}

/// Read the Direct TCP header and bounded payload, returning bytes without the header.
/// Check the marker and size before allocation; use the same deadline for all reads.
pub(super) async fn read_smb_message(
    _reader: &mut (impl AsyncRead + Unpin),
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    Err("SMB Direct TCP response reading is not implemented".into())
}

/// Validate the reply header, message ID, success status, and offered dialect.
/// Map the negotiated protocol as evidence without guessing server software or OS.
pub(super) fn response_information(
    _reply: &[u8],
    _expected_message_id: u64,
) -> Result<ServiceInformation, String> {
    Err("SMB negotiation response validation is not implemented".into())
}
