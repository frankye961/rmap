use std::future::Future;
use std::io;
use std::time::Instant;

use tokio::time::{Instant as Deadline, timeout_at};

use super::AckProbe;
use super::constants::FLAG_RST;
use crate::model::syn::{ParsedIpv4Packet, TcpReply};
use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::scan::raw_tcp::packet::{parse_ipv4_packet, parse_tcp_reply};
use crate::scan::raw_tcp::socket::check_deadline;

/// Reuse IPv4/TCP validation, then match and classify the parsed response.
/// ACK probes need their own correlation rules; do not reuse SYN's ACK-number rule.
pub(super) fn interpret_ack_reply(
    _bytes: &[u8],
    _probe: &AckProbe,
) -> Result<Option<(PortStatus, TcpReply)>, String> {
    let _packet = parse_ipv4_packet(_bytes)?;
    let _reply = parse_tcp_reply(&_packet)?;
    if !match_ack_reply(_probe, &_packet, &_reply)? {
        return Ok(None);
    }
    let _status = match classify_ack_reply(&_reply)? {
        Some(_status) => _status,
        None => return Ok(None),
    };

    Ok(Some((_status, _reply)))
}

/// Check reversed endpoints and the reset sequence against the retained ACK probe.
/// A reply need not carry the ACK flag; its relevant fields differ from SYN replies.
pub(super) fn match_ack_reply(
    _probe: &AckProbe,
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

    if _reply.flags & FLAG_RST == 0 {
        return Ok(false);
    }

    if _reply.sequence_number != _probe.acknowledgment_number {
        return Ok(false);
    }

    Ok(true)
}

/// Classify a validated matching reset as Unfiltered.
/// It establishes neither Open nor Closed. Other replies can remain unclassified.
pub(super) fn classify_ack_reply(_reply: &TcpReply) -> Result<Option<PortStatus>, String> {
    match _reply.flags & FLAG_RST {
        0 => Ok(None),
        _ => Ok(Some(PortStatus::Unfiltered)),
    }
}

/// Ignore unrelated replies under one deadline; the callback supports offline fixtures.
pub(super) async fn wait_for_ack_reply<R, RF>(
    _probe: &AckProbe,
    _deadline: Deadline,
    _receive: &mut R,
) -> io::Result<(PortStatus, TcpReply)>
where
    R: FnMut(Deadline) -> RF,
    RF: Future<Output = io::Result<Vec<u8>>>,
{
    loop {
        check_deadline(_deadline)?;
        let _bytes = timeout_at(_deadline, _receive(_deadline)).await??;
        if let Ok(Some(_result)) = interpret_ack_reply(&_bytes, _probe) {
            return Ok(_result);
        }
        tokio::task::yield_now().await;
    }
}

/// Map received evidence into a measured result; local failures remain undetermined.
/// ACK scanning does not establish a connection requiring SYN-style reset cleanup.
pub(super) async fn finish_ack_probe<R, RF>(
    _probe: &AckProbe,
    _started: Instant,
    _deadline: Deadline,
    _receive: R,
) -> Result<ScanResult, String>
where
    R: FnMut(Deadline) -> RF,
    RF: Future<Output = io::Result<Vec<u8>>>,
{
    let mut _receive = _receive;
    let _outcome = wait_for_ack_reply(_probe, _deadline, &mut _receive).await;
    let mut _result = ScanResult::new(
        _probe.destination.port(),
        ScanMode::Ack,
        PortStatus::Unknown,
        _started.elapsed(),
    );

    match _outcome {
        Ok((_status, _reply)) => {
            _result.status = _status;
            _result.observation = Some(
                "Matching TCP RST received in response to ACK probe; service state is undetermined"
                    .into(),
            );
        }
        Err(_error) if _error.kind() == io::ErrorKind::TimedOut => {
            _result.status = PortStatus::Filtered;
            _result.error = Some(format!(
                "ACK receive timed out; no matching TCP response observed; filtering is unconfirmed: {_error}"
            ));
        }
        Err(_error) => {
            _result.error = Some(format!("Raw TCP ACK receive failed: {_error}"));
        }
    }

    Ok(_result)
}

#[cfg(test)]
#[path = "../../../tests/scan/ack_reply.rs"]
mod tests;
