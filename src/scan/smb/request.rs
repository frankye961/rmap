//! Structured SMB2 NEGOTIATE construction and explicit little-endian encoding.

use super::constants;
use crate::model::smb::{Smb2Header, Smb2Request, Smb2RequestBody};

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
pub(super) fn build_smb2_negotiate_request_body(
    _dialects: &[u16],
    _client_guid: [u8; 16],
) -> Result<Smb2RequestBody, String> {
    if _dialects.is_empty() {
        return Err("SMB2 NEGOTIATE requires at least one dialect".into());
    }
    if _dialects.len() > u16::MAX as usize {
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
pub(super) fn build_smb2_negotiate_request_header(_message_id: u64) -> Result<Smb2Header, String> {
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

/// Encode the header fields in wire order without copying the Rust struct's memory.
pub(super) fn encode_smb2_header(_header: &Smb2Header) -> Result<Vec<u8>, String> {
    let mut _encoded_header = Vec::new();
    _encoded_header.extend_from_slice(&_header.protocol_id);
    _encoded_header.extend_from_slice(&_header.structure_size.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.credit_charge.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.channel_sequence.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.reserved.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.command.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.credit_request.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.flags.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.next_command.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.message_id.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.reserved2.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.tree_id.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.session_id.to_le_bytes());
    _encoded_header.extend_from_slice(&_header.signature);
    Ok(_encoded_header)
}

fn encode_smb2_request_body(_body: &Smb2RequestBody) -> Result<Vec<u8>, String> {
    let mut _encoded_body = Vec::new();
    _encoded_body.extend_from_slice(&_body.structure_size.to_le_bytes());
    _encoded_body.extend_from_slice(&_body.dialect_count.to_le_bytes());
    _encoded_body.extend_from_slice(&_body.security_mode.to_le_bytes());
    _encoded_body.extend_from_slice(&_body.reserved.to_le_bytes());
    _encoded_body.extend_from_slice(&_body.capabilities.to_le_bytes());
    _encoded_body.extend_from_slice(&_body.client_guid);
    _encoded_body.extend_from_slice(&_body.client_start_time.to_le_bytes());
    for &_dialect in &_body.dialects {
        _encoded_body.extend_from_slice(&_dialect.to_le_bytes());
    }
    Ok(_encoded_body)
}

pub(super) fn encode_smb2_request(_request: &Smb2Request) -> Result<Vec<u8>, String> {
    let _encoded_header = encode_smb2_header(&_request.header)?;
    let _encoded_body = encode_smb2_request_body(&_request.body)?;
    let _encoded_request = [_encoded_header, _encoded_body].concat();
    Ok(_encoded_request)
}
