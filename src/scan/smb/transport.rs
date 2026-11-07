//! Bounded SMB Direct TCP framing, connection, and stream exchange.

use super::constants;
use super::request::{build_smb_negotiate_request, encode_smb2_request};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

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
pub(in crate::scan) async fn probe(
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
pub(super) async fn exchange_smb_stream(
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
