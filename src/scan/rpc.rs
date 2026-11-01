//! In-memory RPC request-building exercises, starting with big-endian integers.

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

/// Prefix one RPC message with a final-fragment TCP record marker.
#[allow(dead_code)] // Remove when the RPC probe sends framed requests.
fn frame_rpc_record(_message: &[u8]) -> Result<Vec<u8>, String> {
    let _marker = record_marker(_message.len())?;
    let mut _empty_frame = Vec::new();
    append_u32(&mut _empty_frame, _marker);
    _empty_frame.extend_from_slice(_message);
    Ok(_empty_frame)
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

#[cfg(test)]
#[path = "../../tests/scan/rpc.rs"]
mod tests;
