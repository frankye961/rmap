//! Select bounded identification exchanges and apply evidence without changing measurements.

use super::banner::read_banner;
use crate::mapper::service_information::apply_service_information;
use crate::model::rpc::RpcMapping;
use crate::model::service_information::ServiceInformation;
use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::scan::{http, nfs, rpc, smb};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::Instant as Deadline;

/// Select identification only after a successful connection measurement.
pub(super) async fn collect_service(
    result: &mut ScanResult,
    stream: TcpStream,
    target: SocketAddr,
    timeout: Duration,
) {
    if http::is_http_candidate(target.port()) || http::is_https_candidate(target.port()) {
        drop(stream);
        apply_http_probe_result(result, http::probe(target, timeout).await);
    } else if rpc::is_rpc_candidate(target.port()) {
        // Close the measured connection before opening a probe connection.
        // Descriptor budgeting allows only one live TCP connection per task.
        drop(stream);
        collect_rpc(result, timeout, |_xid, _deadline, _limit| {
            rpc::probe(target, _xid, _deadline, _limit)
        })
        .await;
        collect_rpc_dump(result, timeout, |_xid, _deadline, _limit| {
            rpc::probe_dump(target, _xid, _deadline, _limit)
        })
        .await;
    } else if nfs::is_nfs_candidate(target.port()) {
        drop(stream);
        collect_nfs(result, timeout, |_xid, _deadline, _limit| {
            nfs::probe(target, _xid, _deadline, _limit)
        })
        .await;
    } else if smb::is_smb_candidate(target.port()) {
        drop(stream);
        collect_smb(result, timeout, |_message_id, _guid, _deadline, _limit| {
            smb::probe(target, _message_id, _guid, _deadline, _limit)
        })
        .await;
    } else {
        let (observation, banner) = read_banner(stream, timeout).await;
        result.observation = Some(observation);
        result.banner = banner;
    }
}

pub(super) fn apply_http_probe_result(
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
pub(super) async fn collect_rpc<F, Fut>(_result: &mut ScanResult, _timeout: Duration, _probe: F)
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
    match run_rpc_exchange(_timeout, _probe).await {
        Ok((_xid, _reply)) => apply_rpc_probe_result(_result, Ok(&_reply), _xid),
        Err(_error) => {
            apply_rpc_probe_result(
                _result,
                Err(_error),
                0, // No response is validated on this error path.
            );
        }
    }
}

/// Enumerate only after NULL has identified portmapper; keep identification on failure.
pub(super) async fn collect_rpc_dump<F, Fut>(
    _result: &mut ScanResult,
    _timeout: Duration,
    _probe: F,
) where
    F: FnOnce(u32, Deadline, usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    if _result.transport != ScanMode::Tcp
        || _result.status != PortStatus::Open
        || !rpc::is_rpc_candidate(_result.port)
        || _result.service.as_deref() != Some("rpcbind")
    {
        return;
    }
    let _response = run_rpc_exchange(_timeout, _probe)
        .await
        .and_then(|(_xid, _reply)| {
            rpc::parse_portmapper_dump_reply(&_reply, _xid, rpc::MAX_DUMP_ENTRIES)
        });
    apply_rpc_dump_result(_result, _response);
}

/// Identify NFSv3 on an open TCP candidate without replacing connection measurements.
pub(super) async fn collect_nfs<F, Fut>(_result: &mut ScanResult, _timeout: Duration, _probe: F)
where
    F: FnOnce(u32, Deadline, usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    if _result.transport != ScanMode::Tcp
        || _result.status != PortStatus::Open
        || !nfs::is_nfs_candidate(_result.port)
    {
        return;
    }
    let _response = run_rpc_exchange(_timeout, _probe)
        .await
        .and_then(|(_xid, _reply)| nfs::response_information(&_reply, _xid));
    apply_service_probe_result(_result, _response, "NFS");
}

/// Identify SMB only on an open TCP candidate, preserving connection measurements.
pub(super) async fn collect_smb<F, Fut>(_result: &mut ScanResult, _timeout: Duration, _probe: F)
where
    F: FnOnce(u64, [u8; 16], Deadline, usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    if _result.transport != ScanMode::Tcp
        || _result.status != PortStatus::Open
        || !smb::is_smb_candidate(_result.port)
    {
        return;
    }
    let _deadline = Deadline::now() + _timeout;
    let _response = async {
        let _guid = smb::client_guid()?;
        let _reply = _probe(
            smb::INITIAL_MESSAGE_ID,
            _guid,
            _deadline,
            smb::MAX_REPLY_BYTES,
        )
        .await?;
        smb::response_information(&_reply, smb::INITIAL_MESSAGE_ID)
    }
    .await;
    apply_service_probe_result(_result, _response, "SMB");
}

/// Share XID generation and per-exchange bounds between portmapper and NFS.
async fn run_rpc_exchange<F, Fut>(_timeout: Duration, _probe: F) -> Result<(u32, Vec<u8>), String>
where
    F: FnOnce(u32, Deadline, usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>>,
{
    let _deadline = Deadline::now() + _timeout;
    let _xid = getrandom::u32()
        .map_err(|_error| format!("Failed to generate RPC transaction ID: {_error}"))?;
    let _reply = _probe(_xid, _deadline, rpc::MAX_REPLY_BYTES).await?;
    Ok((_xid, _reply))
}

/// Apply a completed RPC exchange without changing measured connection evidence.
pub(super) fn apply_rpc_probe_result(
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

    let _response = _response.and_then(|_reply| rpc::response_information(_reply, _expected_xid));
    apply_service_probe_result(_result, _response, "RPC");
}

/// Apply validated identification or append a diagnostic, retaining earlier evidence.
fn apply_service_probe_result(
    _result: &mut ScanResult,
    _response: Result<ServiceInformation, String>,
    _protocol: &str,
) {
    let _detail = match _response {
        Ok(_information) => {
            let _detail = _information.observation.clone();
            apply_service_information(_result, _information);
            _detail
        }
        Err(_error) => Some(format!("{_protocol} probe failed: {_error}")),
    };
    if let Some(_detail) = _detail {
        append_observation(_result, &_detail);
    }
}

/// Apply a completed list parse without replacing NULL identification or measurements.
pub(super) fn apply_rpc_dump_result(
    _result: &mut ScanResult,
    _response: Result<Vec<RpcMapping>, String>,
) {
    if _result.transport != ScanMode::Tcp
        || _result.status != PortStatus::Open
        || !rpc::is_rpc_candidate(_result.port)
        || _result.service.as_deref() != Some("rpcbind")
    {
        return;
    }
    match _response {
        Ok(_mappings) => _result.rpc_mappings = Some(_mappings),
        Err(_error) => append_observation(_result, &format!("RPC enumeration failed: {_error}")),
    }
}

fn append_observation(_result: &mut ScanResult, _detail: &str) {
    match _result
        .observation
        .as_mut()
        .filter(|_text| !_text.is_empty())
    {
        Some(_existing) => {
            _existing.push_str("; ");
            _existing.push_str(_detail);
        }
        None => _result.observation = Some(_detail.to_string()),
    }
}
