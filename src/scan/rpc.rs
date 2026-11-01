//! In-memory RPC request-building and reply-validation exercises.

use tokio::io::AsyncRead;
use tokio::time::Instant;

use crate::mapper::service_information::map_portmapper_service;
use crate::model::service_information::ServiceInformation;

/// Select an initial TCP probe candidate; the port alone does not identify RPC.
pub(super) fn is_rpc_candidate(_port: u16) -> bool {
    _port == 111
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
#[allow(dead_code)] // Remove when the RPC request builder uses this helper.
pub(super) fn append_u32(_buffer: &mut Vec<u8>, _value: u32) {
    let _bytes = _value.to_be_bytes();
    _buffer.extend_from_slice(&_bytes);
}

/// Build a 40-byte portmapper v2 NULL call with AUTH_NONE and no TCP framing.
#[allow(dead_code)] // Remove when the TCP-framed RPC probe uses this builder.
pub(super) fn build_portmapper_null_call(_xid: u32) -> Vec<u8> {
    let mut _empty_byte = Vec::new();
    append_u32(&mut _empty_byte, _xid);
    append_u32(&mut _empty_byte, 0);
    append_u32(&mut _empty_byte, 2);
    append_u32(&mut _empty_byte, 100000);
    append_u32(&mut _empty_byte, 2);
    append_u32(&mut _empty_byte, 0);
    append_u32(&mut _empty_byte, 0);
    append_u32(&mut _empty_byte, 0);
    append_u32(&mut _empty_byte, 0);
    append_u32(&mut _empty_byte, 0);
    _empty_byte
}

/// Build a final-fragment marker after checking the 31-bit length limit.
#[allow(dead_code)] // Remove when the TCP framing helper uses this function.
fn record_marker(_length: usize) -> Result<u32, String> {
    if _length > 0x7fff_ffff {
        return Err(format!(
            "RPC fragment length {_length} exceeds the 31-bit maximum of 2147483647 bytes"
        ));
    }

    let u32_size = _length as u32;
    let end_fragment: u32 = 0x8000_0000 | u32_size;
    Ok(end_fragment)
}

/// Decode exactly four marker bytes into (last fragment, payload length).
/// The payload length excludes the marker; the reader must enforce its size limit.
#[allow(dead_code)] // Remove when the RPC record reader uses this helper.
fn decode_record_marker(_marker: &[u8]) -> Result<(bool, usize), String> {
    // Reject input that is not exactly four bytes long.
    // Convert those bytes into a big-endian u32.
    // Check the highest bit (0x8000_0000) for the final-fragment flag.
    // Extract the lower 31 bits (0x7fff_ffff) as the payload length.
    // Return the flag and length; zero-length fragments are valid.
    let _bytes: [u8; 4] = _marker
        .try_into()
        .map_err(|_| "RPC record marker must contain exactly 4 bytes".to_string())?;

    let _converted_bytes = u32::from_be_bytes(_bytes);

    let _last_frag = _converted_bytes & 0x8000_0000 != 0;
    let _length = (_converted_bytes & 0x7fff_ffff) as usize;

    Ok((_last_frag, _length))
}

/// Prefix one RPC message with a final-fragment TCP record marker.
#[allow(dead_code)] // Remove when the RPC probe sends framed requests.
fn frame_rpc_record(_message: &[u8]) -> Result<Vec<u8>, String> {
    let _marker = record_marker(_message.len())?;
    let mut _empty_frame = Vec::new();
    append_u32(&mut _empty_frame, _marker);
    _empty_frame.extend_from_slice(_message);
    Ok(_empty_frame)
}

/// Read one complete RPC record, returning payload bytes without fragment markers.
/// Share one absolute deadline and enforce a total payload limit before allocation.
#[allow(dead_code)] // Remove when the RPC network exchange uses this reader.
async fn read_rpc_record(
    _reader: &mut (impl AsyncRead + Unpin),
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    // Start an empty payload buffer and loop over fragments.
    // Check the deadline each iteration, including for zero-length fragments.
    // Read exactly four marker bytes under _deadline, then decode_record_marker.
    // Use checked addition to reject a total above _max_bytes before growing the buffer.
    // Read the full fragment payload under the same deadline and append it.
    // Return the assembled payload only when the final-fragment flag is set.
    // Return errors for premature EOF, read failures, timeout, or exceeded limits.
    Err("RPC record reading is not implemented yet".into())
}

/// Decode four bytes and advance the cursor only when the entire read succeeds.
#[allow(dead_code)] // Remove when the RPC reply parser uses this helper.
fn read_u32(_data: &[u8], _offset: &mut usize) -> Option<u32> {
    let _current_position = *_offset;
    let _end_position = _current_position.checked_add(4)?;
    let _bytes = _data.get(_current_position.._end_position)?;
    let _value = u32::from_be_bytes([_bytes[0], _bytes[1], _bytes[2], _bytes[3]]);
    *_offset = _end_position;
    Some(_value)
}

/// Validate the transaction ID, REPLY message type, and MSG_ACCEPTED reply status.
/// Input excludes the TCP record marker. Return the cursor after these three fields.
/// An accepted reply still needs its verifier and procedure status checked later.
#[allow(dead_code)] // Remove when the RPC reply parser uses this function.
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
#[allow(dead_code)] // Remove when NULL reply validation uses this helper.
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

/// Validate one complete portmapper NULL reply body, without a TCP record marker.
#[allow(dead_code)] // Remove when the RPC probe validates received replies.
fn validate_portmapper_null_reply(_data: &[u8], _expected_xid: u32) -> Result<(), String> {
    let mut _cursor = validate_rpc_reply_header(_data, _expected_xid)?;
    _cursor = skip_rpc_verifier(_data, _cursor)?;
    let accept_stat = read_u32(_data, &mut _cursor)
        .ok_or_else(|| "Incomplete RPC procedure status: expected 4 bytes".to_string())?;
    if accept_stat != 0 {
        return Err(format!(
            "RPC NULL procedure did not succeed: received accept status {accept_stat}"
        ));
    }

    if _cursor != _data.len() {
        return Err("Unexpected bytes after RPC NULL reply".into());
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/scan/rpc.rs"]
mod tests;
