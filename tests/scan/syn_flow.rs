//! Packet fixtures and orchestration tests: no live scans or raw socket privileges.

use std::cell::Cell;
use std::collections::VecDeque;
use std::future::{pending, ready};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use super::packet::{internet_checksum, parse_ipv4_packet, parse_tcp_reply};
use super::reply::{finish_syn_probe, interpret_syn_reply};
use super::socket::receive_raw_packet;

#[test]
fn raw_socket_permission_errors_explain_privileges_and_preserve_other_errors() {
    let denied =
        super::socket::raw_socket_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert!(denied.contains("CAP_NET_RAW"));
    assert!(denied.contains("sudo"));
    let other =
        super::socket::raw_socket_error(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable));
    assert!(other.contains("Cannot prepare raw TCP socket"));
    assert!(!other.contains("requires raw-socket privileges"));
}
use crate::model::PortStatus;
use crate::model::syn::{ParsedIpv4Packet, SynProbe};
use socket2::{Domain, Socket, Type};
use tokio::io::unix::AsyncFd;

fn probe() -> SynProbe {
    SynProbe {
        source: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 40000),
        destination: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 80),
        sequence_number: 1000,
    }
}

fn refresh_ip_checksum(bytes: &mut [u8]) {
    let length = usize::from(bytes[0] & 0x0f) * 4;
    bytes[10..12].fill(0);
    let checksum = internet_checksum(&bytes[..length]).unwrap();
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn refresh_tcp_checksum(bytes: &mut [u8]) {
    let start = usize::from(bytes[0] & 0x0f) * 4;
    bytes[start + 16..start + 18].fill(0);
    let length = u16::try_from(bytes.len() - start).unwrap();
    // Independent fixture assembly: addresses, zero, protocol, length, segment.
    let mut input = bytes[12..20].to_vec();
    input.extend_from_slice(&[0, 6]);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(&bytes[start..]);
    let checksum = internet_checksum(&input).unwrap();
    bytes[start + 16..start + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn reply_packet(flags: u8, ip_options: usize, tcp_options: usize, payload: &[u8]) -> Vec<u8> {
    assert_eq!(ip_options % 4, 0);
    assert_eq!(tcp_options % 4, 0);
    let probe = probe();
    let ip_length = 20 + ip_options;
    let tcp_length = 20 + tcp_options;
    let total = ip_length + tcp_length + payload.len();
    let mut bytes = vec![0; total];
    bytes[0] = 0x40 | (ip_length / 4) as u8;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[6] = 0x40; // Don't Fragment alone must be accepted.
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&probe.destination.ip().octets());
    bytes[16..20].copy_from_slice(&probe.source.ip().octets());
    bytes[20..ip_length].fill(1); // NOP options.
    let segment = &mut bytes[ip_length..];
    segment[0..2].copy_from_slice(&probe.destination.port().to_be_bytes());
    segment[2..4].copy_from_slice(&probe.source.port().to_be_bytes());
    segment[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    segment[8..12].copy_from_slice(&probe.sequence_number.wrapping_add(1).to_be_bytes());
    segment[12] = ((tcp_length / 4) as u8) << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&1024u16.to_be_bytes());
    segment[20..tcp_length].fill(1);
    segment[tcp_length..].copy_from_slice(payload);
    refresh_tcp_checksum(&mut bytes);
    refresh_ip_checksum(&mut bytes);
    bytes
}

#[test]
fn parsers_handle_options_odd_payload_and_trailing_bytes() {
    let mut bytes = reply_packet(0x12, 4, 4, &[0x80, 0x81, 0x82]);
    let declared_length = bytes.len();
    bytes.extend_from_slice(&[0xee; 5]);
    let parsed = parse_ipv4_packet(&bytes).unwrap();
    assert_eq!(parsed.source, *probe().destination.ip());
    assert_eq!(parsed.destination, *probe().source.ip());
    assert_eq!(parsed.tcp_segment, &bytes[24..declared_length]);
    let reply = parse_tcp_reply(&parsed).unwrap();
    assert_eq!(reply.source_port, 80);
    assert_eq!(reply.destination_port, 40000);
    assert_eq!(reply.sequence_number, 0x1122_3344);
    assert_eq!(reply.acknowledgment_number, 1001);
    assert_eq!(reply.flags, 0x12);
}

#[test]
fn ipv4_parser_rejects_truncation_invalid_lengths_version_protocol_and_checksum() {
    let valid = reply_packet(0x12, 0, 0, &[]);
    for length in 0..valid.len() {
        assert!(
            parse_ipv4_packet(&valid[..length]).is_err(),
            "length {length}"
        );
    }
    for (index, value) in [(0, 0x65), (0, 0x44), (0, 0x4f), (9, 17), (8, 63)] {
        let mut bytes = valid.clone();
        bytes[index] = value;
        assert!(parse_ipv4_packet(&bytes).is_err(), "byte {index}");
    }
    for total in [19u16, 41] {
        let mut bytes = valid.clone();
        bytes[2..4].copy_from_slice(&total.to_be_bytes());
        assert!(parse_ipv4_packet(&bytes).is_err());
    }
}

#[test]
fn ipv4_parser_rejects_fragments_with_valid_header_checksums() {
    for field in [0x2000u16, 1, 0x2001] {
        let mut bytes = reply_packet(0x12, 0, 0, &[]);
        bytes[6..8].copy_from_slice(&field.to_be_bytes());
        refresh_ip_checksum(&mut bytes);
        assert!(
            parse_ipv4_packet(&bytes)
                .unwrap_err()
                .contains("Fragmented")
        );
    }
}

#[test]
fn tcp_parser_rejects_short_headers_bad_offsets_large_segments_and_corruption() {
    let bytes = reply_packet(0x12, 0, 0, &[]);
    let parsed = parse_ipv4_packet(&bytes).unwrap();
    for length in 0..20 {
        let short = ParsedIpv4Packet {
            tcp_segment: &parsed.tcp_segment[..length],
            ..parsed
        };
        assert!(parse_tcp_reply(&short).is_err());
    }
    for offset in [0x40, 0xf0] {
        let mut changed = bytes.clone();
        changed[32] = offset;
        let parsed = parse_ipv4_packet(&changed).unwrap();
        assert!(
            parse_tcp_reply(&parsed)
                .unwrap_err()
                .contains("Header length")
        );
    }
    let mut changed = reply_packet(0x12, 0, 4, &[1, 2, 3]);
    *changed.last_mut().unwrap() ^= 1;
    let parsed = parse_ipv4_packet(&changed).unwrap();
    assert!(parse_tcp_reply(&parsed).unwrap_err().contains("checksum"));

    let mut huge = vec![0; 65536];
    huge[12] = 0x50;
    let parsed = ParsedIpv4Packet {
        tcp_segment: &huge,
        ..parsed
    };
    assert!(parse_tcp_reply(&parsed).unwrap_err().contains("too large"));
}

#[test]
fn interpretation_rejects_each_wrong_endpoint_and_wrong_acknowledgment() {
    let bytes = reply_packet(0x12, 0, 0, &[]);
    for field in 0..4 {
        let mut other = probe();
        match field {
            0 => other.source.set_ip(Ipv4Addr::LOCALHOST),
            1 => other.destination.set_ip(Ipv4Addr::LOCALHOST),
            2 => other.source.set_port(40001),
            _ => other.destination.set_port(81),
        }
        assert!(interpret_syn_reply(&bytes, &other).unwrap().is_none());
    }
    let mut wrong_ack = bytes;
    wrong_ack[28..32].copy_from_slice(&1002u32.to_be_bytes());
    refresh_tcp_checksum(&mut wrong_ack);
    assert!(interpret_syn_reply(&wrong_ack, &probe()).unwrap().is_none());
}

#[tokio::test]
async fn flow_skips_bad_and_unrelated_packets_and_preserves_open_on_cleanup_failure() {
    let probe = probe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut bad_checksum = reply_packet(0x12, 0, 0, &[]);
    bad_checksum[24] ^= 1;
    let mut unrelated = reply_packet(0x12, 0, 0, &[]);
    unrelated[20..22].copy_from_slice(&81u16.to_be_bytes());
    refresh_tcp_checksum(&mut unrelated);
    let mut packets = VecDeque::from([
        vec![0; 3],
        bad_checksum,
        unrelated,
        reply_packet(0x12, 4, 4, &[7]),
    ]);
    let reads = Cell::new(0);
    let cleanups = Cell::new(0);
    let result = finish_syn_probe(
        &probe,
        Instant::now(),
        deadline,
        |passed_deadline| {
            assert_eq!(passed_deadline, deadline);
            reads.set(reads.get() + 1);
            ready(Ok(packets.pop_front().expect("expected matching packet")))
        },
        |reply, cleanup_deadline| {
            assert_eq!(reply.flags, 0x12);
            assert!(cleanup_deadline <= deadline);
            cleanups.set(cleanups.get() + 1);
            ready(Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )))
        },
    )
    .await;
    assert_eq!(reads.get(), 4);
    assert_eq!(cleanups.get(), 1);
    assert_eq!(result.port, 80);
    assert_eq!(result.transport, crate::model::ScanMode::Tcp);
    assert_eq!(result.status, PortStatus::Open);
    assert!(result.error.is_none());
    assert!(result.observation.unwrap().contains("RST cleanup failed"));
    assert!(result.banner.is_none());
    assert!(result.service.is_none());
}

#[tokio::test]
async fn flow_reports_closed_without_cleanup() {
    let cleanups = Cell::new(0);
    let result = finish_syn_probe(
        &probe(),
        Instant::now(),
        tokio::time::Instant::now() + Duration::from_secs(1),
        |_| ready(Ok(reply_packet(0x14, 0, 0, &[]))),
        |_, _| {
            cleanups.set(cleanups.get() + 1);
            ready(Ok(()))
        },
    )
    .await;
    assert_eq!(result.status, PortStatus::Closed);
    assert_eq!(cleanups.get(), 0);
    assert!(result.error.is_none());
    assert!(result.observation.unwrap().contains("RST/ACK"));
}

#[tokio::test]
async fn flow_bounds_silence_and_preserves_local_receive_errors() {
    let silent = finish_syn_probe(
        &probe(),
        Instant::now(),
        tokio::time::Instant::now() + Duration::from_millis(10),
        |_| pending::<std::io::Result<Vec<u8>>>(),
        |_, _| ready(Ok(())),
    )
    .await;
    assert_eq!(silent.status, PortStatus::Filtered);
    assert!(silent.error.unwrap().contains("unconfirmed"));

    let failure = finish_syn_probe(
        &probe(),
        Instant::now(),
        tokio::time::Instant::now() + Duration::from_secs(1),
        |_| {
            ready(Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )))
        },
        |_, _| ready(Ok(())),
    )
    .await;
    assert_eq!(failure.status, PortStatus::Unknown);
    assert!(failure.error.unwrap().contains("receive failed"));
}

#[tokio::test]
async fn expired_flow_does_not_receive_or_cleanup() {
    let result = finish_syn_probe(
        &probe(),
        Instant::now(),
        tokio::time::Instant::now(),
        |_| -> std::future::Ready<std::io::Result<Vec<u8>>> { panic!("receive after deadline") },
        |_, _| -> std::future::Ready<std::io::Result<()>> { panic!("cleanup without reply") },
    )
    .await;
    assert_eq!(result.status, PortStatus::Filtered);
}

#[tokio::test]
async fn raw_receiver_bounds_an_idle_local_pair_and_rejects_expired_deadlines() {
    let (socket, _peer) = Socket::pair(Domain::UNIX, Type::DGRAM, None).unwrap();
    socket.set_nonblocking(true).unwrap();
    // SAFETY: AsyncFd owns this socket and its descriptor remains valid and unchanged.
    let socket = unsafe { AsyncFd::register(socket) }.unwrap();
    let error = receive_raw_packet(
        &socket,
        tokio::time::Instant::now() + Duration::from_millis(10),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let error = receive_raw_packet(&socket, tokio::time::Instant::now())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn unrelated_packet_stream_does_not_extend_the_deadline() {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        finish_syn_probe(
            &probe(),
            Instant::now(),
            deadline,
            |passed_deadline| {
                assert_eq!(passed_deadline, deadline);
                ready(Ok(vec![0; 3]))
            },
            |_, _| ready(Ok(())),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result.status, PortStatus::Filtered);
}

#[tokio::test]
async fn cleanup_timeout_does_not_discard_a_measured_open_port() {
    let result = finish_syn_probe(
        &probe(),
        Instant::now(),
        tokio::time::Instant::now() + Duration::from_millis(10),
        |_| ready(Ok(reply_packet(0x12, 0, 0, &[]))),
        |_, _| pending::<std::io::Result<()>>(),
    )
    .await;
    assert_eq!(result.status, PortStatus::Open);
    assert!(result.error.is_none());
    assert!(result.observation.unwrap().contains("cleanup failed"));
}
