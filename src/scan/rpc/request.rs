//! Encode argument-free ONC RPC calls as XDR words.

use super::constants::*;

/// Append one u32 as four big-endian bytes to the existing buffer.
pub(super) fn append_u32(_buffer: &mut Vec<u8>, _value: u32) {
    let _bytes = _value.to_be_bytes();
    _buffer.extend_from_slice(&_bytes);
}

/// Build a 40-byte portmapper v2 NULL call with AUTH_NONE and no TCP framing.
pub(super) fn build_portmapper_null_call(_xid: u32) -> Vec<u8> {
    build_rpc_call(_xid, PORTMAPPER_PROGRAM, PORTMAPPER_VERSION, NULL_PROCEDURE)
}

/// Build a portmapper v2 DUMP call with AUTH_NONE, without a TCP record marker.
pub(super) fn build_portmapper_dump_call(_xid: u32) -> Vec<u8> {
    build_rpc_call(_xid, PORTMAPPER_PROGRAM, PORTMAPPER_VERSION, DUMP_PROCEDURE)
}

/// Encode the common ten-field header for procedures with no arguments.
pub(in crate::scan) fn build_rpc_call(
    _xid: u32,
    _program: u32,
    _program_version: u32,
    _procedure: u32,
) -> Vec<u8> {
    let mut _call = Vec::with_capacity(CALL_HEADER_BYTES);
    for _field in [
        _xid,
        CALL,
        RPC_VERSION,
        _program,
        _program_version,
        _procedure,
        AUTH_NONE,
        0, // Empty credentials.
        AUTH_NONE,
        0, // Empty verifier.
    ] {
        append_u32(&mut _call, _field);
    }
    _call
}
