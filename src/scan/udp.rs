//! One UDP probe with a bounded wait and uncertain timeout classification.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::utils::banner::escape_bytes;

pub(super) async fn scan_port(target: SocketAddr, timeout: Duration) -> ScanResult {
    let started = Instant::now();
    let mut result = ScanResult {
        port: target.port(),
        transport: ScanMode::Udp,
        status: PortStatus::Unknown,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: None,
        banner: None,
        service_information: None,
    };
    match probe(target, timeout).await {
        Ok((status, observation)) => {
            result.status = status;
            result.observation = Some(observation);
        }
        Err(error) => result.error = Some(error),
    }
    result.elapsed = started.elapsed();
    result
}

async fn probe(target: SocketAddr, timeout: Duration) -> Result<(PortStatus, String), String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|error| format!("Failed to bind local UDP socket: {error}"))?;
    // UDP connect selects a peer and filters incoming datagrams; it sends no handshake.
    socket
        .connect(target)
        .await
        .map_err(|error| format!("Failed to select UDP target: {error}"))?;
    tokio::time::timeout(timeout, socket.send(&[]))
        .await
        .map_err(|_| "UDP send timed out".to_string())?
        .map_err(|error| format!("Failed to send UDP probe: {error}"))?;
    let mut buffer = [0u8; 1024];
    let response = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .unwrap_or_else(|_| Err(io::Error::from(ErrorKind::TimedOut)));
    Ok(classify_response(response, &buffer))
}

fn classify_response(response: io::Result<usize>, buffer: &[u8]) -> (PortStatus, String) {
    match response {
        Ok(size) => {
            let preview = escape_bytes(&buffer[..size], 64);
            let detail = if size == 0 {
                "empty UDP response".into()
            } else if size >= buffer.len() {
                format!("{preview} (preview truncated; datagram may also be truncated)")
            } else if size > 64 {
                format!("{preview} (preview truncated)")
            } else {
                preview
            };
            (PortStatus::Open, detail)
        }
        Err(error) => {
            let status = match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => PortStatus::OpenOrFiltered,
                ErrorKind::ConnectionRefused => PortStatus::Closed,
                _ => PortStatus::Unknown,
            };
            let detail = if status == PortStatus::OpenOrFiltered {
                "no UDP response before read timeout".into()
            } else {
                error.to_string()
            };
            (status, detail)
        }
    }
}

#[cfg(test)]
#[path = "../../tests/scan/udp.rs"]
mod tests;
