use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::time::Instant as Deadline;

use self::constants::TCP_HEADER_BYTES;
use self::probe::prepare_probe;
use self::reply::finish_ack_probe;
use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::scan::raw_tcp::socket::{
    prepare_raw_tcp_socket, raw_socket_error, receive_raw_packet, send_tcp_header,
};

mod constants;
mod packet;
mod probe;
mod reply;

/// Fail before scheduling if raw sockets are unavailable; no packet is sent.
pub(super) fn check_available() -> Result<(), String> {
    prepare_raw_tcp_socket(Ipv4Addr::UNSPECIFIED)
        .map(|_| ())
        .map_err(raw_socket_error)
}

/// Retain exactly the values sent so a response can be correlated with its request.
#[derive(Debug)]
pub(super) struct AckProbe {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
}

/// Keep the source-port reservation and raw socket alive for the whole exchange.
pub(super) struct PreparedProbe {
    pub _source_socket: Socket,
    pub probe: AckProbe,
    pub header: [u8; TCP_HEADER_BYTES],
    pub socket: AsyncFd<Socket>,
}

/// Keep both sockets alive while sending and receiving under the same deadline.
pub(super) async fn scan_port(_target: SocketAddr, _timeout: Duration) -> ScanResult {
    let _started = Instant::now();
    let _prepared = match prepare_probe(_target) {
        Ok(_prepared) => _prepared,
        Err(_error) => return unknown_result(_target, _started.elapsed(), _error),
    };
    let _deadline = Deadline::now() + _timeout;
    let _socket = &_prepared.socket;
    let _probe = &_prepared.probe;

    if let Err(_error) = send_tcp_header(
        _socket,
        &_prepared.header,
        *_probe.destination.ip(),
        _deadline,
    )
    .await
    {
        return unknown_result(
            _target,
            _started.elapsed(),
            format!("Failed to send ACK probe: {_error}"),
        );
    }

    match finish_ack_probe(_probe, _started, _deadline, |_deadline| {
        receive_raw_packet(_socket, _deadline)
    })
    .await
    {
        Ok(_result) => _result,
        Err(_error) => unknown_result(_target, _started.elapsed(), _error),
    }
}

fn unknown_result(_target: SocketAddr, _elapsed: Duration, _error: String) -> ScanResult {
    let mut _result = ScanResult::new(_target.port(), ScanMode::Ack, PortStatus::Unknown, _elapsed);
    _result.error = Some(_error);
    _result
}

#[cfg(test)]
#[path = "../../../tests/scan/ack_flow.rs"]
mod tests;
