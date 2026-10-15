//! Sequential TCP connection attempts and their measured outcomes.

use std::io::ErrorKind;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::model::{PortStatus, ScanResult};

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

        let result = match connection {
            Ok(stream) => {
                let observation = handle_connection(stream, timeout);
                ScanResult {
                    port: target.port(),
                    status: PortStatus::Open,
                    elapsed,
                    error: None,
                    observation: Some(observation),
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
                    status,
                    elapsed,
                    error: Some(error.to_string()),
                    observation: None,
                }
            }
        };
        results.push(result);
    }

    results
}

fn handle_connection(mut stream: TcpStream, timeout: Duration) -> String {
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        return format!("could not set read timeout: {error}");
    }

    let mut buffer = [0; 512];
    match stream.read(&mut buffer) {
        Ok(0) => "peer closed without sending data".to_string(),
        Ok(bytes_read) => {
            let preview_len = bytes_read.min(64);
            let preview: String = buffer[..preview_len]
                .iter()
                .flat_map(|byte| std::ascii::escape_default(*byte))
                .map(char::from)
                .collect();
            if bytes_read > preview_len {
                format!("{bytes_read} bytes: \"{preview}\" (first {preview_len} shown)")
            } else {
                format!("{bytes_read} bytes: \"{preview}\"")
            }
        }
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            "no data before read timeout".to_string()
        }
        Err(error) => format!("read error: {error}"),
    }
}
