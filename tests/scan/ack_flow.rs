//! ACK entry-point failure checks that never create a socket or send a packet.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use super::{AckProbe, packet::build_ack_header, scan_port};
use crate::model::{PortStatus, ScanMode};

#[test]
fn outgoing_ack_header_matches_an_independently_calculated_wire_fixture() {
    let probe = AckProbe {
        source: SocketAddrV4::new([192, 0, 2, 10].into(), 40000),
        destination: SocketAddrV4::new([198, 51, 100, 20].into(), 443),
        sequence_number: 0x1020_3040,
        acknowledgment_number: 0x89ab_cdef,
    };
    // Independent pseudo-header + one's-complement sum gives TCP checksum 0x898b.
    let expected = [
        0x9c, 0x40, 0x01, 0xbb, 0x10, 0x20, 0x30, 0x40, 0x89, 0xab, 0xcd, 0xef, 0x50, 0x10, 0x04,
        0x00, 0x89, 0x8b, 0x00, 0x00,
    ];
    assert_eq!(build_ack_header(&probe, 1024).unwrap(), expected);
}

#[tokio::test]
async fn unsupported_target_is_a_local_failure_without_service_evidence() {
    let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
    let started = Instant::now();

    // IPv6 is rejected before route selection, source-port reservation, or raw I/O.
    let result = scan_port(target, Duration::from_secs(1)).await;

    assert_eq!(result.port, 443);
    assert_eq!(result.transport, ScanMode::Tcp);
    assert_eq!(result.method, ScanMode::Ack);
    assert_eq!(result.status, PortStatus::Unknown);
    assert_eq!(
        result.error.as_deref(),
        Some("ACK probing supports IPv4 only; IPv6 is not supported")
    );
    assert!(result.elapsed <= started.elapsed());
    assert!(result.observation.is_none());
    assert!(result.service.is_none());
    assert!(result.banner.is_none());
    assert!(result.service_information.is_none());
    assert!(result.rpc_mappings.is_none());
}
