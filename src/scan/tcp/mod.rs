//! Measure TCP connections; service identification never replaces the measured state.

use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::scan::identify;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

mod banner;
mod service;

pub(super) async fn scan_port(target: SocketAddr, timeout: Duration) -> ScanResult {
    let started = Instant::now();
    let connection = tokio::time::timeout(timeout, TcpStream::connect(target))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(ErrorKind::TimedOut)));
    let elapsed = started.elapsed();

    let mut result = ScanResult::new(target.port(), ScanMode::Tcp, PortStatus::Open, elapsed);
    match connection {
        Ok(stream) => service::collect_service(&mut result, stream, target, timeout).await,
        Err(error) => {
            result.status = match error.kind() {
                ErrorKind::ConnectionRefused => PortStatus::Closed,
                ErrorKind::TimedOut => PortStatus::Filtered,
                _ => PortStatus::Unknown,
            };
            result.error = Some(error.to_string());
        }
    }
    identify::collect_banner(&mut result);
    result
}

#[cfg(test)]
#[path = "../../../tests/scan/tcp.rs"]
mod tests;
