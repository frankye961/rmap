//! Bounded TCP RPC exchanges, reply validation, and portmapper enumeration.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::mapper::service_information::map_portmapper_service;
use crate::model::rpc::RpcMapping;
use crate::model::service_information::ServiceInformation;

/// Bound the assembled reply; protocol version 2 NULL replies need far less space.
pub(super) const MAX_REPLY_BYTES: usize = 4096;

/// Bound the number of advertised registrations independently of the byte limit.
pub(super) const MAX_DUMP_ENTRIES: usize = 128;

/// Select an initial TCP probe candidate; the port alone does not identify RPC.
pub(super) fn is_rpc_candidate(_port: u16) -> bool {
    _port == 111
}

/// Exchange one portmapper NULL call over TCP under the caller's shared deadline.
/// Return the assembled reply body; the result handler validates it against _xid.
pub(super) async fn probe(
    _target: SocketAddr,
    _xid: u32,
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let _null_call = build_portmapper_null_call(_xid);
    exchange_rpc_call(_target, &_null_call, _deadline, _max_bytes).await
}

/// Exchange a DUMP request; the caller validates and parses its list payload.
pub(super) async fn probe_dump(
    _target: SocketAddr,
    _xid: u32,
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let _dump_call = build_portmapper_dump_call(_xid);
    exchange_rpc_call(_target, &_dump_call, _deadline, _max_bytes).await
}

/// Connect once for either procedure, sharing the same deadline with stream I/O.
pub(super) async fn exchange_rpc_call(
    _target: SocketAddr,
    _message: &[u8],
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let _frame = frame_rpc_record(_message)?;
    if Instant::now() >= _deadline {
        return Err("RPC connection timed out".into());
    }
    let mut _connection = tokio::time::timeout_at(_deadline, TcpStream::connect(_target))
        .await
        .map_err(|_| "RPC connection timed out".to_string())?
        .map_err(|_error| format!("RPC connection failed: {_error}"))?;

    exchange_rpc_stream(&mut _connection, &_frame, _deadline, _max_bytes).await
}

/// Reuse the request/response sequence with a TCP stream or in-memory test stream.
async fn exchange_rpc_stream(
    _connection: &mut (impl AsyncRead + AsyncWrite + Unpin),
    _frame: &[u8],
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if Instant::now() >= _deadline {
        return Err("RPC request writing timed out".into());
    }
    tokio::time::timeout_at(_deadline, _connection.write_all(_frame))
        .await
        .map_err(|_| "RPC request writing timed out".to_string())?
        .map_err(|_error| format!("Failed to write RPC request: {_error}"))?;

    let _reply = read_rpc_record(_connection, _deadline, _max_bytes)
        .await
        .map_err(|_error| format!("Failed to read RPC record: {_error}"))?;

    Ok(_reply)
}

/// Validate a complete, reassembled reply body before mapping service information.
/// The caller must remove TCP record markers and retain the request's XID.
pub(super) fn response_information(
    _reply: &[u8],
    _expected_xid: u32,
) -> Result<ServiceInformation, String> {
    validate_portmapper_null_reply(_reply, _expected_xid)?;
    Ok(map_portmapper_service())
}

/// Append one u32 as four big-endian bytes to the existing buffer.
pub(super) fn append_u32(_buffer: &mut Vec<u8>, _value: u32) {
    let _bytes = _value.to_be_bytes();
    _buffer.extend_from_slice(&_bytes);
}

/// Build a 40-byte portmapper v2 NULL call with AUTH_NONE and no TCP framing.
pub(super) fn build_portmapper_null_call(_xid: u32) -> Vec<u8> {
    build_rpc_call(_xid, 100000, 2, 0)
}

/// Build a portmapper v2 DUMP call with AUTH_NONE, without a TCP record marker.
fn build_portmapper_dump_call(_xid: u32) -> Vec<u8> {
    build_rpc_call(_xid, 100000, 2, 4)
}

/// Encode the common ten-field header for procedures with no arguments.
pub(super) fn build_rpc_call(
    _xid: u32,
    _program: u32,
    _program_version: u32,
    _procedure: u32,
) -> Vec<u8> {
    let mut _call = Vec::with_capacity(40);
    for _field in [
        _xid,
        0, // CALL.
        2, // RPC protocol version.
        _program,
        _program_version,
        _procedure,
        0,
        0, // Empty AUTH_NONE credentials.
        0,
        0, // Empty AUTH_NONE verifier.
    ] {
        append_u32(&mut _call, _field);
    }
    _call
}

/// Build a final-fragment marker after checking the 31-bit length limit.
fn record_marker(_length: usize) -> Result<u32, String> {
    if _length > 0x7fff_ffff {
        return Err(format!(
            "RPC fragment length {_length} exceeds the 31-bit maximum of 2147483647 bytes"
        ));
    }

    Ok(0x8000_0000 | _length as u32)
}

/// Decode exactly four marker bytes into (last fragment, payload length).
/// The payload length excludes the marker; the reader must enforce its size limit.
fn decode_record_marker(_marker: &[u8]) -> Result<(bool, usize), String> {
    let _bytes: [u8; 4] = _marker
        .try_into()
        .map_err(|_| "RPC record marker must contain exactly 4 bytes".to_string())?;

    let _converted_bytes = u32::from_be_bytes(_bytes);

    let _last_frag = _converted_bytes & 0x8000_0000 != 0;
    let _length = (_converted_bytes & 0x7fff_ffff) as usize;

    Ok((_last_frag, _length))
}

/// Prefix one RPC message with a final-fragment TCP record marker.
fn frame_rpc_record(_message: &[u8]) -> Result<Vec<u8>, String> {
    let _marker = record_marker(_message.len())?;
    let mut _frame = Vec::new();
    append_u32(&mut _frame, _marker);
    _frame.extend_from_slice(_message);
    Ok(_frame)
}

/// Read one complete RPC record, returning payload bytes without fragment markers.
/// Share one absolute deadline and enforce a total payload limit before allocation.
async fn read_rpc_record(
    _reader: &mut (impl AsyncRead + Unpin),
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut _payload: Vec<u8> = Vec::new();
    loop {
        if Instant::now() >= _deadline {
            return Err("RPC record reading timed out".into());
        }
        let mut _marker_bytes = [0u8; 4];
        match tokio::time::timeout_at(_deadline, _reader.read_exact(&mut _marker_bytes)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(format!("Failed to read RPC record marker: {error}"));
            }
            Err(_) => {
                return Err("RPC record reading timed out".into());
            }
        }

        let (_last_frag, _frag_length) = decode_record_marker(&_marker_bytes)?;
        let _len = _payload.len().checked_add(_frag_length).ok_or_else(|| {
            format!(
                "RPC record length overflow: current payload {} + fragment {}",
                _payload.len(),
                _frag_length
            )
        })?;
        if _len > _max_bytes {
            return Err(format!(
                "RPC record exceeded maximum allowed payload of {_max_bytes} bytes"
            ));
        }
        let mut _frag_bytes = vec![0u8; _frag_length];
        match tokio::time::timeout_at(_deadline, _reader.read_exact(&mut _frag_bytes)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(format!("Failed to read RPC fragment: {error}"));
            }
            Err(_) => {
                return Err("RPC fragment reading timed out".into());
            }
        }
        _payload.extend_from_slice(&_frag_bytes);
        if _last_frag {
            return Ok(_payload);
        }
    }
}

/// Decode four bytes and advance the cursor only when the entire read succeeds.
fn read_u32(_data: &[u8], _offset: &mut usize) -> Option<u32> {
    let _current_position = *_offset;
    let _end_position = _current_position.checked_add(4)?;
    let _bytes = _data.get(_current_position.._end_position)?;
    let _value = u32::from_be_bytes([_bytes[0], _bytes[1], _bytes[2], _bytes[3]]);
    *_offset = _end_position;
    Some(_value)
}

/// Read one 16-byte mapping, advancing the caller's cursor only on success.
fn read_rpc_mapping(_data: &[u8], _offset: &mut usize) -> Result<RpcMapping, String> {
    let mut _cursor = *_offset;
    let _program = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC program number: expected 4 bytes".to_string())?;
    let _version = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC program version: expected 4 bytes".to_string())?;
    let _protocol = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC protocol number: expected 4 bytes".to_string())?;
    let _port = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC port number: expected 4 bytes".to_string())?;
    if _port == 0 || _port > 65535 {
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
fn validate_rpc_reply_header(_data: &[u8], _expected_xid: u32) -> Result<usize, String> {
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

    if _message_type_reply != 1 {
        return Err(format!(
            "Expected RPC REPLY (1), received message type {_message_type_reply}"
        ));
    }

    if _status_reply != 0 {
        return Err(format!(
            "Expected RPC MSG_ACCEPTED (0), received reply status {_status_reply}"
        ));
    }
    Ok(_offset)
}

/// Check the verifier's structure and return the cursor after its padded body.
/// This only checks encoding and bounds; it does not authenticate the server.
fn skip_rpc_verifier(_data: &[u8], _offset: usize) -> Result<usize, String> {
    let mut _cursor = _offset;
    let _flavor = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC verifier flavor: expected 4 bytes".to_string())?;

    let _body_len = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC verifier body length: expected 4 bytes".to_string())?;

    if _body_len > 400 {
        return Err(format!(
            "RPC verifier body length {_body_len} exceeds the maximum of 400 bytes"
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
pub(super) fn validate_rpc_success_reply(
    _data: &[u8],
    _expected_xid: u32,
) -> Result<usize, String> {
    let mut _cursor = validate_rpc_reply_header(_data, _expected_xid)?;
    _cursor = skip_rpc_verifier(_data, _cursor)?;
    let accept_stat = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC procedure status: expected 4 bytes".to_string())?;
    if accept_stat != 0 {
        return Err(format!(
            "RPC procedure did not succeed: received accept status {accept_stat}"
        ));
    }

    Ok(_cursor)
}

/// Validate one complete portmapper NULL reply body, without a TCP record marker.
fn validate_portmapper_null_reply(_data: &[u8], _expected_xid: u32) -> Result<(), String> {
    let _cursor = validate_rpc_success_reply(_data, _expected_xid)?;
    if _cursor != _data.len() {
        return Err("Unexpected bytes after RPC NULL reply".into());
    }

    Ok(())
}

/// Parse a complete successful DUMP reply into advertised registrations.
pub(super) fn parse_portmapper_dump_reply(
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

#[cfg(test)]
#[path = "../../tests/scan/rpc.rs"]
mod tests;
