//! Future ACK reply correlation, classification and bounded reception.

use std::future::Future;
use std::time::Instant;

use tokio::time::Instant as Deadline;

use super::AckProbe;
use super::constants::FLAG_RST;
use crate::model::syn::{ParsedIpv4Packet, TcpReply};
use crate::model::{PortStatus, ScanResult};

/// Reuse IPv4/TCP validation, then match and classify the parsed response.
/// ACK probes need their own correlation rules; do not reuse SYN's ACK-number rule.
pub(super) fn interpret_ack_reply(
    _bytes: &[u8],
    _probe: &AckProbe,
) -> Result<Option<(PortStatus, TcpReply)>, String> {
    Err("ACK reply interpretation is not implemented".into())
}

/// Check reversed endpoints and the reset sequence against the retained ACK probe.
/// A reply need not carry the ACK flag; its relevant fields differ from SYN replies.
pub(super) fn match_ack_reply(
    _probe: &AckProbe,
    _packet: &ParsedIpv4Packet<'_>,
    _reply: &TcpReply,
) -> Result<bool, String> {
    let _probe_dest_port = _probe.destination.port();
    let _probe_source_port = _probe.source.port();
    let _probe_dest_addr = _probe.destination.ip();
    let _probe_source_addr = _probe.source.ip();
    let _packet_source_addr = _packet.source;
    let _packet_destination_addr = _packet.destination;
    let _reply_source_port = _reply.source_port;
    let _reply_destination_port = _reply.destination_port;

    if _packet_source_addr != *_probe_dest_addr {
        return Ok(false);
    }

    if _packet_destination_addr != *_probe_source_addr {
        return Ok(false);
    }

    if _reply_source_port != _probe_dest_port {
        return Ok(false);
    }

    if _reply_destination_port != _probe_source_port {
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

/// Classify a validated matching reset as Unfiltered once that model state exists.
/// It establishes neither Open nor Closed. Other replies can remain unclassified.
pub(super) fn classify_ack_reply(_reply: &TcpReply) -> Result<Option<PortStatus>, String> {
    Err("ACK reply classification is not implemented".into())
}

/// Ignore unrelated replies under one deadline; the callback supports offline fixtures.
pub(super) async fn wait_for_ack_reply<R, RF>(
    _probe: &AckProbe,
    _deadline: Deadline,
    _receive: &mut R,
) -> std::io::Result<(PortStatus, TcpReply)>
where
    R: FnMut(Deadline) -> RF,
    RF: Future<Output = std::io::Result<Vec<u8>>>,
{
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ACK reception is not implemented",
    ))
}

/// Future response handling and result mapping; local failures must remain undetermined.
/// ACK scanning does not establish a connection requiring SYN-style reset cleanup.
pub(super) async fn finish_ack_probe<R, RF>(
    _probe: &AckProbe,
    _started: Instant,
    _deadline: Deadline,
    _receive: R,
) -> Result<ScanResult, String>
where
    R: FnMut(Deadline) -> RF,
    RF: Future<Output = std::io::Result<Vec<u8>>>,
{
    Err("ACK result handling is not implemented".into())
}

#[cfg(test)]
#[path = "../../../tests/scan/ack_reply.rs"]
mod tests;
