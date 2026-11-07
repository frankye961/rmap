//! One RPC connection and exchange under an absolute deadline.

use super::record::{frame_rpc_record, read_rpc_record};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

/// Connect once for either procedure, sharing the same deadline with stream I/O.
pub(in crate::scan) async fn exchange_rpc_call(
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
pub(super) async fn exchange_rpc_stream(
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
