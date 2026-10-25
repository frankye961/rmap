//! Correlate validated replies and preserve measurements through bounded cleanup.

use super::packet::{parse_ipv4_packet, parse_tcp_reply};
use super::unknown_result;
use crate::mapper::syn::map_syn_result;
use crate::model::syn::{ParsedIpv4Packet, SynProbe, TcpReply};
use crate::model::{PortStatus, ScanResult};
use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Orchestrate reply handling. I/O callbacks allow tests to inject packets and
/// failures without opening raw sockets or contacting a host.
pub(super) async fn finish_syn_probe<R, C, RF, CF>(
    _probe: &SynProbe,
    _started: Instant,
    _deadline: tokio::time::Instant,
    mut _receive: R,
    mut _cleanup: C,
) -> ScanResult
where
    R: FnMut(tokio::time::Instant) -> RF,
    RF: Future<Output = std::io::Result<Vec<u8>>>,
    C: FnMut(TcpReply, tokio::time::Instant) -> CF,
    CF: Future<Output = std::io::Result<()>>,
{
    let target = SocketAddr::V4(_probe.destination);
    let (status, reply) = match wait_for_syn_reply(_probe, _deadline, &mut _receive).await {
        Ok(result) => result,
        Err(error) => return receive_failure(target, _started.elapsed(), error),
    };
    // Measure the response before cleanup, so cleanup latency cannot change it.
    let elapsed = _started.elapsed();
    let mut observation = if status == PortStatus::Open {
        "Matching TCP SYN/ACK received".to_string()
    } else {
        "Matching TCP RST/ACK received".to_string()
    };
    let warning = if status == PortStatus::Open {
        cleanup_diagnostic(reply, _deadline, &mut _cleanup).await
    } else {
        None
    };
    if let Some(warning) = warning {
        observation.push_str(&format!("; RST cleanup failed: {warning}"));
    }
    map_syn_result(target, status, elapsed, None, Some(observation))
}

/// Discard malformed/unrelated packets without resetting the deadline or starving tasks.
async fn wait_for_syn_reply<R, RF>(
    _probe: &SynProbe,
    _deadline: tokio::time::Instant,
    _receive: &mut R,
) -> std::io::Result<(PortStatus, TcpReply)>
where
    R: FnMut(tokio::time::Instant) -> RF,
    RF: Future<Output = std::io::Result<Vec<u8>>>,
{
    loop {
        super::socket::check_deadline(_deadline)?;
        let bytes = tokio::time::timeout_at(_deadline, _receive(_deadline))
            .await
            .map_err(|_| super::socket::timeout_error())??;
        if let Ok(Some(result)) = interpret_syn_reply(&bytes, _probe) {
            return Ok(result);
        }
        tokio::task::yield_now().await;
    }
}

fn receive_failure(_target: SocketAddr, _elapsed: Duration, _error: std::io::Error) -> ScanResult {
    if _error.kind() == std::io::ErrorKind::TimedOut {
        return map_syn_result(
            _target,
            PortStatus::Filtered,
            _elapsed,
            Some("No matching TCP response before SYN deadline; filtering is unconfirmed".into()),
            None,
        );
    }
    unknown_result(
        _target,
        _elapsed,
        format!("Raw TCP receive failed: {_error}"),
    )
}

/// Keep cleanup bounded and return a warning instead of replacing measured status.
async fn cleanup_diagnostic<C, CF>(
    _reply: TcpReply,
    _deadline: tokio::time::Instant,
    _cleanup: &mut C,
) -> Option<String>
where
    C: FnMut(TcpReply, tokio::time::Instant) -> CF,
    CF: Future<Output = std::io::Result<()>>,
{
    let deadline = _deadline.min(tokio::time::Instant::now() + Duration::from_millis(100));
    match tokio::time::timeout_at(deadline, _cleanup(_reply, deadline)).await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some(super::socket::timeout_error().to_string()),
    }
}

/// Parse and correlate a raw packet before deriving any measured state.
pub(super) fn interpret_syn_reply(
    _bytes: &[u8],
    _probe: &SynProbe,
) -> Result<Option<(PortStatus, TcpReply)>, String> {
    let packet = parse_ipv4_packet(_bytes)?;
    let reply = parse_tcp_reply(&packet)?;
    if !match_syn_reply(_probe, &packet, &reply)? {
        return Ok(None);
    }
    Ok(classify_syn_reply(&reply)?.map(|status| (status, reply)))
}

/// Compare reversed addresses and ports, acknowledgment, and acceptable flags
/// against the original probe. Use wrapping sequence arithmetic; ignore unrelated replies.
pub(super) fn match_syn_reply(
    _probe: &SynProbe,
    _packet: &ParsedIpv4Packet<'_>,
    _reply: &TcpReply,
) -> Result<bool, String> {
    if _packet.source != *_probe.destination.ip() {
        return Ok(false);
    }

    if _packet.destination != *_probe.source.ip() {
        return Ok(false);
    }

    if _reply.source_port != _probe.destination.port() {
        return Ok(false);
    }

    if _reply.destination_port != _probe.source.port() {
        return Ok(false);
    }

    let expected_ack = _probe.sequence_number.wrapping_add(1);

    if _reply.flags & 0x10 == 0 {
        return Ok(false);
    }

    if expected_ack != _reply.acknowledgment_number {
        return Ok(false);
    }

    Ok(classify_syn_reply(_reply)?.is_some())
}

/// Classify an already validated and matched reply. Return None for a flag
/// combination that does not establish a supported outcome; timeouts are handled separately.
pub(super) fn classify_syn_reply(_reply: &TcpReply) -> Result<Option<PortStatus>, String> {
    let _fin = _reply.flags & 0x01 != 0;
    let _syn = _reply.flags & 0x02 != 0;
    let _rst = _reply.flags & 0x04 != 0;
    let _ack = _reply.flags & 0x10 != 0;

    if !_ack || _fin || _syn == _rst {
        return Ok(None);
    }

    if _syn {
        Ok(Some(PortStatus::Open))
    } else {
        Ok(Some(PortStatus::Closed))
    }
}
