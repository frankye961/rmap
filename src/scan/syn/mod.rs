//! IPv4 SYN discovery: prepare a probe, send it, then process matching replies.

use std::net::Ipv4Addr;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::Socket;
use tokio::io::unix::AsyncFd;

use crate::mapper::syn::map_syn_result;
use crate::model::syn::{SynProbe, TcpReply};
use crate::model::{PortStatus, ScanResult};

mod packet;
mod reply;
mod socket;

/// Fail before scheduling ports if raw socket setup is unavailable. No packets sent.
pub(super) fn check_available() -> Result<(), String> {
    socket::prepare_raw_tcp_socket(Ipv4Addr::UNSPECIFIED)
        .map(|_| ())
        .map_err(socket::raw_socket_error)
}

/// Own the reservation and registered raw socket for the entire probe lifetime.
struct PreparedProbe {
    _source_socket: Socket,
    probe: SynProbe,
    header: [u8; 20],
    socket: AsyncFd<Socket>,
}

pub(super) async fn scan_port(target: SocketAddr, timeout: Duration) -> ScanResult {
    let started = Instant::now();
    let prepared = match prepare_probe(target) {
        Ok(prepared) => prepared,
        Err(error) => return unknown_result(target, started.elapsed(), error),
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let socket = &prepared.socket;
    let probe = &prepared.probe;
    if let Err(error) =
        socket::send_tcp_header(socket, &prepared.header, *probe.destination.ip(), deadline).await
    {
        return unknown_result(
            target,
            started.elapsed(),
            format!("Failed to send SYN probe: {error}"),
        );
    }
    reply::finish_syn_probe(
        probe,
        started,
        deadline,
        |deadline| socket::receive_raw_packet(socket, deadline),
        |reply, deadline| async move { cleanup_syn_probe(socket, probe, &reply, deadline).await },
    )
    .await
}

/// Setup errors remain local errors; no packet has been sent at this point.
fn prepare_probe(target: SocketAddr) -> Result<PreparedProbe, String> {
    let destination = match target {
        SocketAddr::V4(destination) => destination,
        SocketAddr::V6(_) => return Err("IPv6 is not supported for SYN scanning".into()),
    };
    let source_ip = socket::discover_source_ip(destination)
        .map_err(|error| format!("Failed to determine local source IP: {error}"))?;
    let (source_socket, source_port) = socket::create_unconnected_tcp_socket(source_ip)
        .map_err(|error| format!("Failed to reserve TCP source port: {error}"))?;
    let sequence_number = generate_sequence_number()
        .map_err(|error| format!("Failed to generate SYN sequence number: {error}"))?;
    let probe = SynProbe {
        source: SocketAddrV4::new(source_ip, source_port),
        destination,
        sequence_number,
    };
    let header = packet::build_syn_header(
        source_ip,
        *destination.ip(),
        source_port,
        destination.port(),
        sequence_number,
        1024,
    )?;
    let raw = socket::prepare_raw_tcp_socket(source_ip).map_err(socket::raw_socket_error)?;
    let socket = socket::register_raw_socket(raw)?;
    Ok(PreparedProbe {
        _source_socket: source_socket,
        probe,
        header,
        socket,
    })
}

/// Obtain a sequence number from the operating system's random source.
fn generate_sequence_number() -> Result<u32, getrandom::Error> {
    getrandom::u32()
}

fn unknown_result(target: SocketAddr, elapsed: Duration, error: String) -> ScanResult {
    map_syn_result(target, PortStatus::Unknown, elapsed, Some(error), None)
}

/// Cleanup cannot erase the measured state; reply validation is the caller's job.
async fn cleanup_syn_probe(
    _socket: &AsyncFd<Socket>,
    _probe: &SynProbe,
    _reply: &TcpReply,
    _deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    let status = reply::classify_syn_reply(_reply)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if status != Some(PortStatus::Open) {
        return Ok(());
    }
    let reset_header = packet::build_rst_header(_probe, _reply)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    socket::send_tcp_header(_socket, &reset_header, *_probe.destination.ip(), _deadline).await
}

#[cfg(test)]
#[path = "../../../tests/scan/syn.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/scan/syn_flow.rs"]
mod flow_tests;
