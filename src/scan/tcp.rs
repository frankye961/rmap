//! One TCP connection attempt with passive banners or HTTP, HTTPS, and RPC probes.

use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;

use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::{Instant as Deadline, timeout_at};

use super::{http, identify, rpc};
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
            } else if rpc::is_rpc_candidate(target.port()) {
                // Keep only one connection per task, as required by descriptor budgeting.
                drop(stream);
                collect_rpc(&mut result, timeout, |_xid, _deadline, _limit| {
                    rpc::probe(target, _xid, _deadline, _limit)
                })
                .await;
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

/// Run the selected exchange separately from connection measurement and result mapping.
async fn collect_rpc<F, Fut>(_result: &mut ScanResult, _timeout: Duration, _probe: F)
where
    F: FnOnce(u32, Deadline, usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    if _result.transport != ScanMode::Tcp
        || _result.status != PortStatus::Open
        || !rpc::is_rpc_candidate(_result.port)
    {
        return;
    }
    let _deadline = Deadline::now() + _timeout;
    let _xid = match getrandom::u32() {
        Ok(_xid) => _xid,
        Err(_error) => {
            apply_rpc_probe_result(
                _result,
                Err(format!("Failed to generate RPC transaction ID: {_error}")),
                0, // No response is validated on this error path.
            );
            return;
        }
    };
    let _response = _probe(_xid, _deadline, rpc::MAX_REPLY_BYTES).await;
    apply_rpc_probe_result(_result, _response.as_deref().map_err(String::clone), _xid);
}

/// Apply a completed RPC exchange without changing measured connection evidence.
fn apply_rpc_probe_result(
    _result: &mut ScanResult,
    _response: Result<&[u8], String>,
    _expected_xid: u32,
) {
    if _result.transport != ScanMode::Tcp
        || _result.status != PortStatus::Open
        || !rpc::is_rpc_candidate(_result.port)
    {
        return;
    }

    let _detail =
        match _response.and_then(|_reply| rpc::response_information(_reply, _expected_xid)) {
            Ok(_information) => {
                let _detail = _information.observation.clone();
                apply_service_information(_result, _information);
                _detail
            }
            Err(_error) => Some(format!("RPC probe failed: {_error}")),
        };
    if let Some(_detail) = _detail {
        match _result
            .observation
            .as_mut()
            .filter(|_text| !_text.is_empty())
        {
            Some(_existing) => {
                _existing.push_str("; ");
                _existing.push_str(&_detail);
            }
            None => _result.observation = Some(_detail),
        }
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
