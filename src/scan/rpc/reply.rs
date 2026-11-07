//! Validate RPC reply envelopes and decode advertised portmapper registrations.

use super::constants::*;
use crate::model::rpc::RpcMapping;

/// Decode four bytes and advance the cursor only when the entire read succeeds.
pub(super) fn read_u32(_data: &[u8], _offset: &mut usize) -> Option<u32> {
    let _current_position = *_offset;
    let _end_position = _current_position.checked_add(4)?;
    let _bytes = _data.get(_current_position.._end_position)?;
    let _value = u32::from_be_bytes([_bytes[0], _bytes[1], _bytes[2], _bytes[3]]);
    *_offset = _end_position;
    Some(_value)
}

/// Read one 16-byte mapping, advancing the caller's cursor only on success.
pub(super) fn read_rpc_mapping(_data: &[u8], _offset: &mut usize) -> Result<RpcMapping, String> {
    let mut _cursor = *_offset;
    let _program = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC program number: expected 4 bytes".to_string())?;
    let _version = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC program version: expected 4 bytes".to_string())?;
    let _protocol = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC protocol number: expected 4 bytes".to_string())?;
    let _port = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC port number: expected 4 bytes".to_string())?;
    if _port == 0 || _port > u32::from(u16::MAX) {
        return Err(format!("RPC port number {_port} is out of range 1..=65535"));
    }

    let _mapping = RpcMapping {
        program: _program,
        program_version: _version,
        protocol: _protocol,
        port: _port,
    };
    *_offset = _cursor;
    Ok(_mapping)
}

/// Validate the transaction ID, REPLY message type, and MSG_ACCEPTED reply status.
/// Input excludes the TCP record marker. Return the cursor after these three fields.
/// An accepted reply still needs its verifier and procedure status checked later.
pub(super) fn validate_rpc_reply_header(_data: &[u8], _expected_xid: u32) -> Result<usize, String> {
    let mut _offset = 0;
    let _xid = read_u32(_data, &mut _offset)
        .ok_or_else(|| "Incomplete RPC transaction ID: expected 4 bytes".to_string())?;
    let _message_type_reply = read_u32(_data, &mut _offset)
        .ok_or_else(|| "Incomplete RPC message type: expected 4 bytes".to_string())?;

    let _status_reply = read_u32(_data, &mut _offset)
        .ok_or_else(|| "Incomplete RPC reply status: expected 4 bytes".to_string())?;

    if _xid != _expected_xid {
        return Err("RPC transaction ID does not match the request".into());
    }

    if _message_type_reply != REPLY {
        return Err(format!(
            "Expected RPC REPLY (1), received message type {_message_type_reply}"
        ));
    }

    if _status_reply != MSG_ACCEPTED {
        return Err(format!(
            "Expected RPC MSG_ACCEPTED (0), received reply status {_status_reply}"
        ));
    }
    Ok(_offset)
}

/// Check the verifier's structure and return the cursor after its padded body.
/// This only checks encoding and bounds; it does not authenticate the server.
pub(super) fn skip_rpc_verifier(_data: &[u8], _offset: usize) -> Result<usize, String> {
    let mut _cursor = _offset;
    let _flavor = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC verifier flavor: expected 4 bytes".to_string())?;

    let _body_len = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC verifier body length: expected 4 bytes".to_string())?;

    if _body_len > MAX_VERIFIER_BYTES {
        return Err(format!(
            "RPC verifier body length {_body_len} exceeds the maximum of {MAX_VERIFIER_BYTES} bytes"
        ));
    }

    let _body_len = _body_len as usize;
    let _body_end = _cursor
        .checked_add(_body_len)
        .ok_or_else(|| "RPC verifier body position overflow".to_string())?;
    let _body = _data
        .get(_cursor.._body_end)
        .ok_or_else(|| "Incomplete RPC verifier body".to_string())?;

    // XDR adds zero bytes until the body occupies a multiple of four bytes.
    let _padding_len = (4 - _body_len % 4) % 4;
    let _padding_end = _body_end
        .checked_add(_padding_len)
        .ok_or_else(|| "RPC verifier padding position overflow".to_string())?;
    let _padding = _data
        .get(_body_end.._padding_end)
        .ok_or_else(|| "Incomplete RPC verifier padding".to_string())?;
    if _padding.iter().any(|_byte| *_byte != 0) {
        return Err("RPC verifier padding must contain only zero bytes".into());
    }

    Ok(_padding_end)
}

/// Validate the common successful reply envelope and return its result-body offset.
pub(in crate::scan) fn validate_rpc_success_reply(
    _data: &[u8],
    _expected_xid: u32,
) -> Result<usize, String> {
    let mut _cursor = validate_rpc_reply_header(_data, _expected_xid)?;
    _cursor = skip_rpc_verifier(_data, _cursor)?;
    let accept_stat = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC procedure status: expected 4 bytes".to_string())?;
    if accept_stat != SUCCESS {
        return Err(format!(
            "RPC procedure did not succeed: received accept status {accept_stat}"
        ));
    }

    Ok(_cursor)
}

/// Validate one complete portmapper NULL reply body, without a TCP record marker.
pub(super) fn validate_portmapper_null_reply(
    _data: &[u8],
    _expected_xid: u32,
) -> Result<(), String> {
    let _cursor = validate_rpc_success_reply(_data, _expected_xid)?;
    if _cursor != _data.len() {
        return Err("Unexpected bytes after RPC NULL reply".into());
    }

    Ok(())
}

/// Parse a complete successful DUMP reply into advertised registrations.
pub(in crate::scan) fn parse_portmapper_dump_reply(
    _data: &[u8],
    _expected_xid: u32,
    _max_entries: usize,
) -> Result<Vec<RpcMapping>, String> {
    let mut _cursor = validate_rpc_success_reply(_data, _expected_xid)?;
    let mut _mappings = Vec::new();
    loop {
        let _list_marker = read_u32(_data, &mut _cursor)
            .ok_or_else(|| "Incomplete RPC list marker: expected 4 bytes".to_string())?;
        if _list_marker == 0 {
            if _cursor != _data.len() {
                return Err("Unexpected bytes after RPC DUMP list".into());
            }
            return Ok(_mappings);
        }
        if _list_marker != 1 {
            return Err(format!(
                "Unexpected RPC list marker {_list_marker}: expected 0 or 1"
            ));
        }
        if _mappings.len() >= _max_entries {
            return Err(format!(
                "RPC DUMP reply exceeded maximum of {_max_entries} entries"
            ));
        }
        let _mapping = read_rpc_mapping(_data, &mut _cursor)?;
        _mappings.push(_mapping);
    }
}
