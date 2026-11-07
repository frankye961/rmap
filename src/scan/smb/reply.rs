//! Validate SMB2 negotiation evidence without inferring server software or OS.

use super::constants;
use crate::model::service_information::ServiceInformation;

/// Validate the reply header, message ID, success status, and offered dialect.
/// Map the negotiated protocol as evidence without guessing server software or OS.
pub(in crate::scan) fn response_information(
    _reply: &[u8],
    _expected_message_id: u64,
) -> Result<ServiceInformation, String> {
    validate_reply_header(_reply, _expected_message_id)?;
    let _negotiated_dialect = validate_negotiate_body(_reply)?;
    Ok(crate::mapper::service_information::map_tcp_service(
        "smb",
        None,
        None,
        Some(&format!(
            "SMB protocol dialect {_negotiated_dialect:#06x} negotiated successfully"
        )),
    ))
}

/// Validate one synchronous NEGOTIATE reply before reading its procedure body.
/// Input starts at the SMB2 header, after the Direct TCP framing was removed.
fn validate_reply_header(_reply: &[u8], _expected_message_id: u64) -> Result<(), String> {
    if _reply.len() < constants::HEADER_STRUCTURE_SIZE as usize {
        return Err("SMB reply is too short to contain a valid header".into());
    }

    if _reply[0..4] != constants::PROTOCOL_ID {
        return Err("SMB reply has an invalid protocol ID".into());
    }
    if _reply[4..6] != constants::HEADER_STRUCTURE_SIZE.to_le_bytes() {
        return Err("SMB reply has an invalid header structure size".into());
    }
    if _reply[12..14] != constants::NEGOTIATE_COMMAND.to_le_bytes() {
        return Err("SMB reply is not a NEGOTIATE response".into());
    }
    let _flags = u32::from_le_bytes([_reply[16], _reply[17], _reply[18], _reply[19]]);
    if _flags & constants::SERVER_TO_REDIR == 0 {
        return Err("SMB reply is missing the server response flag".into());
    }
    if _flags & constants::ASYNC_COMMAND != 0 {
        return Err("SMB asynchronous negotiation replies are not supported".into());
    }
    if _reply[20..24] != constants::NO_NEXT_COMMAND.to_le_bytes() {
        return Err("SMB compounded negotiation replies are not supported".into());
    }
    if _reply[24..32] != _expected_message_id.to_le_bytes() {
        return Err("SMB reply has an unexpected message ID".into());
    }
    let _status = u32::from_le_bytes([_reply[8], _reply[9], _reply[10], _reply[11]]);
    if _status != constants::STATUS_SUCCESS {
        return Err(format!(
            "SMB negotiation failed with status {_status:#010x}"
        ));
    }
    Ok(())
}

/// Validate the fixed response body and return a dialect offered by this probe.
fn validate_negotiate_body(_reply: &[u8]) -> Result<u16, String> {
    if _reply.len() < constants::MIN_NEGOTIATE_RESPONSE_SIZE {
        return Err("SMB reply is too short to contain the fixed NEGOTIATE response".into());
    }
    if _reply[64..66] != constants::NEGOTIATE_RESPONSE_STRUCTURE_SIZE.to_le_bytes() {
        return Err("SMB reply has an invalid NEGOTIATE response structure size".into());
    }
    let _dialect = u16::from_le_bytes([_reply[68], _reply[69]]);
    if !matches!(_dialect, constants::DIALECT_2_0_2 | constants::DIALECT_2_1) {
        return Err("SMB reply offers an unexpected dialect".into());
    }
    validate_security_buffer(_reply)?;
    Ok(_dialect)
}

/// Check buffer bounds after fixed-body validation; do not interpret authentication data.
fn validate_security_buffer(_reply: &[u8]) -> Result<(), String> {
    let _offset = usize::from(u16::from_le_bytes([_reply[120], _reply[121]]));
    let _length = usize::from(u16::from_le_bytes([_reply[122], _reply[123]]));
    if _length == 0 {
        return Ok(());
    }
    let _end = _offset
        .checked_add(_length)
        .ok_or_else(|| "SMB security buffer range overflow".to_string())?;
    if _offset < constants::MIN_NEGOTIATE_RESPONSE_SIZE || _end > _reply.len() {
        return Err("SMB security buffer is outside the response payload".into());
    }
    Ok(())
}
