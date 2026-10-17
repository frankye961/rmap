//! Sequential TCP scans, passive banners, and the HTTP probe.

use std::io::ErrorKind;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::{http, identify};
use crate::model::{PortStatus, ScanMode, ScanResult};

pub fn scan(address: String, timeout: Duration, ports: &[&str]) -> Vec<ScanResult> {
    let mut results = Vec::new();

    for port in ports {
        let target = match format!("{address}:{port}").parse::<SocketAddr>() {
            Ok(target) => target,
            Err(error) => {
                eprintln!("Invalid target address {address}:{port}: {error}");
                continue;
            }
        };

        let started = Instant::now();
        let connection = TcpStream::connect_timeout(&target, timeout);
        let elapsed = started.elapsed();

        let mut result = match connection {
            Ok(stream) => {
                let (service, observation, banner) = if target.port() == 80 {
                    drop(stream);
                    match http::probe(target, timeout) {
                        Ok(response) => (Some("http".to_string()), response, None),
                        Err(error) => (None, Some(format!("HTTP probe failed: {error}")), None),
                    }
                } else {
                    let (observation, banner) = handle_connection(stream, timeout);
                    (None, Some(observation), banner)
                };
                ScanResult {
                    port: target.port(),
                    transport: ScanMode::Tcp,
                    status: PortStatus::Open,
                    service,
                    elapsed,
                    error: None,
                    observation,
                    banner,
                    service_information: None,
                }
            }
            Err(error) => {
                let status = match error.kind() {
                    ErrorKind::ConnectionRefused => PortStatus::Closed,
                    ErrorKind::TimedOut => PortStatus::Filtered,
                    _ => PortStatus::Unknown,
                };
                ScanResult {
                    port: target.port(),
                    transport: ScanMode::Tcp,
                    status,
                    service: None,
                    elapsed,
                    error: Some(error.to_string()),
                    observation: None,
                    banner: None,
                    service_information: None,
                }
            }
        };
        identify::collect_banner(&mut result);
        results.push(result);
    }

    results
}

fn handle_connection(mut stream: TcpStream, timeout: Duration) -> (String, Option<Vec<u8>>) {
    let mut buffer = [0; 512];
    let mut collected = Vec::new();
    let start = Instant::now();
    for buffer in buffer.chunks_mut(64) {
        let remaining_timeout = calculate_remaning_timeout(start, timeout);
        if remaining_timeout.is_zero() {
            return banner_result(&collected, "read timed out");
        }
        if let Err(error) = stream.set_read_timeout(Some(remaining_timeout)) {
            return banner_result(&collected, &format!("could not set read timeout: {error}"));
        }
        match stream.read(buffer) {
            Ok(0) => return banner_result(&collected, "peer closed connection"),
            Ok(bytes_read) => {
                collected.extend_from_slice(&buffer[..bytes_read]);
                if collected.contains(&b'\n') || collected.len() >= 512 {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return banner_result(&collected, "read timed out");
            }
            Err(error) => return banner_result(&collected, &format!("read error: {error}")),
        }
    }
    banner_result(&collected, "")
}

fn calculate_remaning_timeout(started: Instant, timeout: Duration) -> Duration {
    let elapsed = started.elapsed();
    if elapsed >= timeout {
        Duration::from_secs(0)
    } else {
        timeout - elapsed
    }
}

fn banner_result(data: &[u8], stop_reason: &str) -> (String, Option<Vec<u8>>) {
    let observation = if data.is_empty() && stop_reason.is_empty() {
        "no banner received".to_string()
    } else {
        stop_reason.to_string()
    };
    (observation, Some(data.to_vec()))
}

#[cfg(test)]
#[path = "../../tests/scan/tcp.rs"]
mod tests;
