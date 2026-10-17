//! Sequential UDP probes with bounded waits and uncertain timeout classification.

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::model::{PortStatus, ScanMode, ScanResult};

pub fn scan(address: String, timeout: Duration, ports: &[&str]) -> Result<Vec<ScanResult>, String> {
    if timeout.is_zero() {
        return Err("UDP timeout must be greater than zero".into());
    }
    // Validate all targets before sending any probes.
    let targets = ports
        .iter()
        .map(|port| {
            format!("{address}:{port}")
                .parse::<SocketAddr>()
                .map_err(|error| format!("Invalid UDP target {address}:{port}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut results = Vec::new();
    for target in targets {
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
        };
        match probe(target, timeout) {
            Ok((status, observation)) => {
                result.status = status;
                result.observation = Some(observation);
            }
            Err(error) => result.error = Some(error),
        }
        result.elapsed = started.elapsed();
        results.push(result);
    }
    Ok(results)
}

fn probe(target: SocketAddr, timeout: Duration) -> Result<(PortStatus, String), String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| format!("Failed to bind local UDP socket: {error}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(|error| format!("Failed to set UDP timeout: {error}"))?;
    // UDP connect selects a peer and filters incoming datagrams; it sends no handshake.
    socket
        .connect(target)
        .map_err(|error| format!("Failed to select UDP target: {error}"))?;
    socket
        .send(&[])
        .map_err(|error| format!("Failed to send UDP probe: {error}"))?;
    let mut buffer = [0u8; 1024];
    Ok(classify_response(socket.recv(&mut buffer), &buffer))
}

fn classify_response(response: io::Result<usize>, buffer: &[u8]) -> (PortStatus, String) {
    match response {
        Ok(size) => {
            let preview: String = buffer[..size.min(64)]
                .iter()
                .flat_map(|byte| std::ascii::escape_default(*byte))
                .map(char::from)
                .collect();
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
