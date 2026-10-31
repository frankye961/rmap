//! One TCP connection attempt with optional passive banner or HTTP probing.

use std::io::ErrorKind;
use std::net::SocketAddr;

use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::{Instant as Deadline, timeout_at};

use super::{http, identify};
use crate::mapper::service_information::apply_service_information;
use crate::model::service_information::ServiceInformation;
use crate::model::{PortStatus, ScanMode, ScanResult};

pub(super) async fn scan_port(target: SocketAddr, timeout: Duration) -> ScanResult {
    let started = Instant::now();
    let connection = tokio::time::timeout(timeout, TcpStream::connect(target))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(ErrorKind::TimedOut)));
    let elapsed = started.elapsed();

    let mut result = match connection {
        Ok(stream) => {
            let mut result = ScanResult {
                port: target.port(),
                transport: ScanMode::Tcp,
                status: PortStatus::Open,
                service: None,
                elapsed,
                error: None,
                observation: None,
                banner: None,
                service_information: None,
            };
            if http::is_http_candidate(target.port()) || http::is_https_candidate(target.port()) {
                drop(stream);
                apply_http_probe_result(&mut result, http::probe(target, timeout).await);
            } else {
                let (observation, banner) = read_banner(stream, timeout).await;
                result.observation = Some(observation);
                result.banner = banner;
            }
            result
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
    result
}

fn apply_http_probe_result(
    result: &mut ScanResult,
    response: Result<(ServiceInformation, Option<String>), reqwest::Error>,
) {
    match response {
        Ok((information, observation)) => {
            apply_service_information(result, information);
            result.observation = observation;
        }
        Err(error) => result.observation = Some(format!("HTTP probe failed: {error}")),
    }
}

async fn read_banner(
    mut stream: impl AsyncRead + Unpin,
    timeout: Duration,
) -> (String, Option<Vec<u8>>) {
    let mut buffer = [0; 64];
    let mut collected = Vec::new();
    let deadline = Deadline::now() + timeout;
    while collected.len() < 512 {
        // One deadline bounds the entire banner, including repeated short reads.
        if Deadline::now() >= deadline {
            return banner_result(&collected, "read timed out");
        }
        let capacity = buffer.len().min(512 - collected.len());
        let read = match timeout_at(deadline, stream.read(&mut buffer[..capacity])).await {
            Ok(read) => read,
            Err(_) => return banner_result(&collected, "read timed out"),
        };
        match read {
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
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return banner_result(&collected, &format!("read error: {error}")),
        }
    }
    banner_result(&collected, "")
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
