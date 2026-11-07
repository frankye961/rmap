//! Bounded SMB2 negotiation and validated identification on open TCP port 445.

use std::net::SocketAddr;
use std::sync::OnceLock;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::model::service_information::ServiceInformation;
use crate::model::smb_2_header::Smb2Header;
use crate::model::smb_2_request::Smb2Request;
use crate::model::smb_2_request_body::Smb2RequestBody;

mod constants;

/// The first request on a fresh SMB connection uses message ID zero.
pub(super) const INITIAL_MESSAGE_ID: u64 = 0;

/// Bound identification replies independently of the transport's 24-bit wire limit.
pub(super) const MAX_REPLY_BYTES: usize = 4096;

/// Reuse one randomly generated client identifier across this process's SMB probes.
pub(super) fn client_guid() -> Result<[u8; 16], String> {
    static GUID: OnceLock<Result<[u8; 16], String>> = OnceLock::new();
    GUID.get_or_init(|| {
        let mut _guid = [0; 16];
        getrandom::fill(&mut _guid)
            .map_err(|_error| format!("Failed to generate SMB client GUID: {_error}"))?;
        Ok(_guid)
    })
    .clone()
}

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
    if _message.len() > constants::MAX_DIRECT_TCP_PAYLOAD {
        return Err("SMB Direct TCP payload exceeds 24-bit length limit".into());
    }

    let _length = _message.len() as u32;
    let _framed_message = [
        &[0u8],                        // Direct TCP marker
        &(_length.to_be_bytes()[1..]), // 3-byte network-order length
        _message,
    ]
    .concat();
    Ok(_framed_message)
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
    if Instant::now() >= _deadline {
        return Err("SMB Direct TCP connection deadline has already passed".into());
    }
    let _request = build_smb_negotiate_request(_message_id, _client_guid)?;
    let _framed_request =
        encode_smb2_request(&_request).and_then(|bytes| frame_smb_message(&bytes))?;
    let mut _connection = timeout_at(_deadline, TcpStream::connect(_target))
        .await
        .map_err(|_| "SMB Direct TCP connection timed out".to_string())?
        .map_err(|e| format!("SMB Direct TCP connection failed: {e}"))?;

    exchange_smb_stream(&mut _connection, &_framed_request, _deadline, _max_bytes).await
}

/// Share the exchange sequence between a TCP stream and offline in-memory streams.
async fn exchange_smb_stream(
    _connection: &mut (impl AsyncRead + AsyncWrite + Unpin),
    _framed_request: &[u8],
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if Instant::now() >= _deadline {
        return Err("SMB Direct TCP write deadline has already passed".into());
    }
    timeout_at(_deadline, _connection.write_all(_framed_request))
        .await
        .map_err(|_| "SMB Direct TCP write timed out".to_string())?
        .map_err(|e| format!("SMB Direct TCP write failed: {e}"))?;

    read_smb_message(_connection, _deadline, _max_bytes).await
}

/// Read the Direct TCP header and bounded payload, returning bytes without the header.
/// Check the marker and size before allocation; use the same deadline for all reads.
pub(super) async fn read_smb_message(
    _reader: &mut (impl AsyncRead + Unpin),
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if Instant::now() >= _deadline {
        return Err("SMB Direct TCP read deadline has already passed".into());
    }
    let mut _buffer = [0u8; 4];
    timeout_at(_deadline, _reader.read_exact(&mut _buffer))
        .await
        .map_err(|_| "SMB Direct TCP read timed out".to_string())?
        .map_err(|e| format!("SMB Direct TCP read error: {e}"))?;
    if _buffer[0] != 0 {
        return Err("SMB Direct TCP message is missing the zero marker".into());
    }
    let _length = u32::from_be_bytes([0, _buffer[1], _buffer[2], _buffer[3]]) as usize;
    if _length > _max_bytes {
        return Err(format!(
            "SMB Direct TCP payload length {_length} exceeds caller's limit of {_max_bytes} bytes"
        ));
    }
    if Instant::now() >= _deadline {
        return Err("SMB Direct TCP payload read deadline has already passed".into());
    }
    let mut _payload = vec![0u8; _length];
    timeout_at(_deadline, _reader.read_exact(&mut _payload))
        .await
        .map_err(|_| "SMB Direct TCP payload read timed out".to_string())?
        .map_err(|e| format!("SMB Direct TCP payload read error: {e}"))?;
    Ok(_payload)
}

/// Validate the reply header, message ID, success status, and offered dialect.
/// Map the negotiated protocol as evidence without guessing server software or OS.
pub(super) fn response_information(
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

/// Encode the header fields in wire order without copying the Rust struct's memory.
fn encode_smb2_header(_header: &Smb2Header) -> Result<Vec<u8>, String> {
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

fn encode_smb2_request(_request: &Smb2Request) -> Result<Vec<u8>, String> {
    let _encoded_header = encode_smb2_header(&_request.header)?;
    let _encoded_body = encode_smb2_request_body(&_request.body)?;
    let _encoded_request = [_encoded_header, _encoded_body].concat();
    Ok(_encoded_request)
}

#[cfg(test)]
#[path = "../../tests/scan/smb.rs"]
mod tests;
