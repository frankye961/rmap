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
                handle_connection(stream, target.port(), timeout);
                ScanResult {
                    port: target.port(),
                    status: PortStatus::Open,
                    elapsed,
                    error: None,
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
                }
            }
        };
        results.push(result);
    }

    results
}

fn handle_connection(mut stream: TcpStream, port: u16, timeout: Duration) {
    if let Err(error) = stream.set_read_timeout(Some(timeout)) {
        eprintln!("Could not set a read timeout for port {port}: {error}");
        return;
    }

    let mut buffer = [0; 512];
    match stream.read(&mut buffer) {
        Ok(0) => println!("Port {port}: connection closed by peer"),
        Ok(bytes_read) => {
            println!("Received {bytes_read} bytes: {:?}", &buffer[..bytes_read]);
        }
        Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            println!("Port {port}: no data received before the read timeout");
        }
        Err(error) => eprintln!("Could not read from port {port}: {error}"),
    }
}
