//! TCP record framing and bounded fragment reassembly.

use super::constants::{FINAL_FRAGMENT, FRAGMENT_LENGTH_MASK};
use super::request::append_u32;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Instant;

/// Build a final-fragment marker after checking the 31-bit length limit.
pub(super) fn record_marker(_length: usize) -> Result<u32, String> {
    if _length > FRAGMENT_LENGTH_MASK as usize {
        return Err(format!(
            "RPC fragment length {_length} exceeds the 31-bit maximum of 2147483647 bytes"
        ));
    }

    Ok(FINAL_FRAGMENT | _length as u32)
}

/// Decode exactly four marker bytes into (last fragment, payload length).
/// The payload length excludes the marker; the reader must enforce its size limit.
pub(super) fn decode_record_marker(_marker: &[u8]) -> Result<(bool, usize), String> {
    let _bytes: [u8; 4] = _marker
        .try_into()
        .map_err(|_| "RPC record marker must contain exactly 4 bytes".to_string())?;

    let _converted_bytes = u32::from_be_bytes(_bytes);

    let _last_frag = _converted_bytes & FINAL_FRAGMENT != 0;
    let _length = (_converted_bytes & FRAGMENT_LENGTH_MASK) as usize;

    Ok((_last_frag, _length))
}

/// Prefix one RPC message with a final-fragment TCP record marker.
pub(super) fn frame_rpc_record(_message: &[u8]) -> Result<Vec<u8>, String> {
    let _marker = record_marker(_message.len())?;
    let mut _frame = Vec::new();
    append_u32(&mut _frame, _marker);
    _frame.extend_from_slice(_message);
    Ok(_frame)
}

/// Read one complete RPC record, returning payload bytes without fragment markers.
/// Share one absolute deadline and enforce a total payload limit before allocation.
pub(super) async fn read_rpc_record(
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
        read_exact(
            _reader,
            &mut _marker_bytes,
            _deadline,
            "Failed to read RPC record marker",
            "RPC record reading timed out",
        )
        .await?;

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
        read_exact(
            _reader,
            &mut _frag_bytes,
            _deadline,
            "Failed to read RPC fragment",
            "RPC fragment reading timed out",
        )
        .await?;
        _payload.extend_from_slice(&_frag_bytes);
        if _last_frag {
            return Ok(_payload);
        }
    }
}

async fn read_exact(
    reader: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
    deadline: Instant,
    read_error: &str,
    timeout_error: &str,
) -> Result<(), String> {
    tokio::time::timeout_at(deadline, reader.read_exact(buffer))
        .await
        .map_err(|_| timeout_error.to_string())?
        .map_err(|error| format!("{read_error}: {error}"))?;
    Ok(())
}
