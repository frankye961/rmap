//! Packet fixtures and receive-loop checks; no sockets or live probes.

use std::cell::Cell;
use std::collections::VecDeque;
use std::future::{pending, ready};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use tokio::time::Instant as Deadline;

use super::{
    classify_ack_reply, finish_ack_probe, interpret_ack_reply, match_ack_reply, wait_for_ack_reply,
};
use crate::model::syn::{ParsedIpv4Packet, TcpReply};
use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::scan::ack::AckProbe;

// Independent IPv4/TCP fixture: 198.51.100.20:443 -> 192.0.2.10:40000.
// IP checksum 0x7c4a; TCP checksum 0xc9f7; no production encoder is used here.
const RESET_PACKET: [u8; 40] = [
    0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06, 0x7c, 0x4a, 0xc6, 0x33, 0x64, 0x14,
    0xc0, 0x00, 0x02, 0x0a, 0x01, 0xbb, 0x9c, 0x40, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x04, 0x04, 0x00, 0xc9, 0xf7, 0x00, 0x00,
];

fn matching_reset() -> (AckProbe, ParsedIpv4Packet<'static>, TcpReply) {
    let probe = AckProbe {
        source: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 40000),
        destination: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 443),
        sequence_number: 0x1020_3040,
        acknowledgment_number: 0x89ab_cdef,
    };
    let packet = ParsedIpv4Packet {
        source: *probe.destination.ip(),
        destination: *probe.source.ip(),
        tcp_segment: &[], // Parsing precedes matching; this function uses parsed fields.
    };
    let reply = TcpReply {
        source_port: probe.destination.port(),
        destination_port: probe.source.port(),
        sequence_number: probe.acknowledgment_number,
        acknowledgment_number: 0,
        flags: 0x04, // Independent wire value for RST, without ACK.
    };
    (probe, packet, reply)
}

#[test]
fn accepts_matching_reset_without_an_ack_flag() {
    let (probe, packet, reply) = matching_reset();
    assert!(match_ack_reply(&probe, &packet, &reply).unwrap());
}

#[test]
fn accepts_matching_reset_with_an_ack_flag_without_using_its_acknowledgment_field() {
    let (probe, packet, mut reply) = matching_reset();
    reply.flags = 0x14; // RST | ACK.
    reply.acknowledgment_number = 0xdead_beef;
    assert!(match_ack_reply(&probe, &packet, &reply).unwrap());
}

#[test]
fn rejects_packets_without_rst_even_with_matching_endpoints_and_sequence() {
    for flags in [0x00, 0x01, 0x02, 0x10, 0x12] {
        let (probe, packet, mut reply) = matching_reset();
        reply.flags = flags;
        assert!(
            !match_ack_reply(&probe, &packet, &reply).unwrap(),
            "Accepted non-reset flags {flags:#04x}"
        );
    }
}

#[test]
fn rejects_wrong_reset_sequences_including_the_syn_sequence_rule() {
    let (probe, packet, mut reply) = matching_reset();
    reply.acknowledgment_number = probe.sequence_number.wrapping_add(1);
    for sequence in [
        probe.acknowledgment_number ^ 1,
        probe.sequence_number,
        probe.sequence_number.wrapping_add(1),
    ] {
        reply.sequence_number = sequence;
        assert!(!match_ack_reply(&probe, &packet, &reply).unwrap());
    }
}

#[test]
fn matches_zero_and_maximum_acknowledgments_without_incrementing_them() {
    for acknowledgment in [0, u32::MAX] {
        let (mut probe, packet, mut reply) = matching_reset();
        probe.acknowledgment_number = acknowledgment;
        reply.sequence_number = acknowledgment;
        assert!(match_ack_reply(&probe, &packet, &reply).unwrap());

        reply.sequence_number = acknowledgment.wrapping_add(1);
        assert!(!match_ack_reply(&probe, &packet, &reply).unwrap());
    }
}

#[test]
fn rejects_each_incorrect_endpoint_even_with_valid_reset_correlation() {
    for changed_field in 0..4 {
        let (probe, mut packet, mut reply) = matching_reset();
        match changed_field {
            0 => packet.source = Ipv4Addr::new(203, 0, 113, 1),
            1 => packet.destination = Ipv4Addr::new(203, 0, 113, 2),
            2 => reply.source_port += 1,
            _ => reply.destination_port += 1,
        }
        assert!(!match_ack_reply(&probe, &packet, &reply).unwrap());
    }
}

#[test]
fn classifies_bare_and_ack_bearing_resets_as_unfiltered() {
    for flags in [0x04, 0x14] {
        let (_, _, mut reply) = matching_reset();
        reply.flags = flags;
        assert_eq!(
            classify_ack_reply(&reply).unwrap(),
            Some(PortStatus::Unfiltered)
        );
    }
}

#[test]
fn leaves_non_reset_packets_unclassified() {
    for flags in [0x00, 0x01, 0x02, 0x10, 0x12] {
        let (_, _, mut reply) = matching_reset();
        reply.flags = flags;
        assert_eq!(classify_ack_reply(&reply).unwrap(), None);
    }
}

#[test]
fn interprets_a_valid_matching_packet_and_retains_reply_fields() {
    let (probe, _, _) = matching_reset();
    let (status, reply) = interpret_ack_reply(&RESET_PACKET, &probe)
        .unwrap()
        .expect("A matching reset should produce an observation");
    assert_eq!(status, PortStatus::Unfiltered);
    assert_eq!(reply.source_port, 443);
    assert_eq!(reply.destination_port, 40000);
    assert_eq!(reply.sequence_number, 0x89ab_cdef);
    assert_eq!(reply.acknowledgment_number, 0);
    assert_eq!(reply.flags, 0x04);
}

#[test]
fn ignores_valid_packets_for_another_endpoint_or_probe_number() {
    let (mut probe, _, _) = matching_reset();
    probe.destination.set_port(444);
    assert!(
        interpret_ack_reply(&RESET_PACKET, &probe)
            .unwrap()
            .is_none()
    );

    let (mut probe, _, _) = matching_reset();
    probe.acknowledgment_number ^= 1;
    assert!(
        interpret_ack_reply(&RESET_PACKET, &probe)
            .unwrap()
            .is_none()
    );
}

#[test]
fn ignores_a_valid_non_reset_packet() {
    let (probe, _, _) = matching_reset();
    let mut packet = RESET_PACKET;
    packet[33] = 0x10; // ACK without RST.
    packet[36..38].copy_from_slice(&[0xc9, 0xeb]); // Recalculated fixture checksum.
    assert!(interpret_ack_reply(&packet, &probe).unwrap().is_none());
}

#[test]
fn reports_truncation_and_checksum_errors_instead_of_an_unrelated_packet() {
    let (probe, _, _) = matching_reset();
    let mut bad_ip_checksum = RESET_PACKET;
    bad_ip_checksum[8] ^= 1;
    let mut bad_tcp_checksum = RESET_PACKET;
    bad_tcp_checksum[24] ^= 1;

    for packet in [
        Vec::new(),
        RESET_PACKET[..39].to_vec(),
        bad_ip_checksum.to_vec(),
        bad_tcp_checksum.to_vec(),
    ] {
        assert!(interpret_ack_reply(&packet, &probe).is_err());
    }
}

#[tokio::test]
async fn receive_loop_returns_the_first_matching_reset_and_preserves_reply_fields() {
    let (probe, _, expected) = matching_reset();
    let deadline = Deadline::now() + Duration::from_secs(1);
    let reads = Cell::new(0);
    let mut receive = |passed_deadline| {
        assert_eq!(passed_deadline, deadline);
        reads.set(reads.get() + 1);
        ready(Ok(RESET_PACKET.to_vec()))
    };

    let (status, reply) = wait_for_ack_reply(&probe, deadline, &mut receive)
        .await
        .unwrap();

    assert_eq!(reads.get(), 1);
    assert_eq!(status, PortStatus::Unfiltered);
    assert_eq!(reply.source_port, expected.source_port);
    assert_eq!(reply.destination_port, expected.destination_port);
    assert_eq!(reply.sequence_number, expected.sequence_number);
    assert_eq!(reply.acknowledgment_number, expected.acknowledgment_number);
    assert_eq!(reply.flags, expected.flags);
}

#[tokio::test]
async fn receive_loop_skips_malformed_unrelated_and_non_reset_packets_under_one_deadline() {
    let (probe, _, _) = matching_reset();
    let mut unrelated = RESET_PACKET;
    unrelated[21] = 0xbc; // Source port 444 instead of 443.
    unrelated[36..38].copy_from_slice(&[0xc9, 0xf6]); // Independent fixture checksum.
    assert!(interpret_ack_reply(&unrelated, &probe).unwrap().is_none());

    let mut non_reset = RESET_PACKET;
    non_reset[33] = 0x10;
    non_reset[36..38].copy_from_slice(&[0xc9, 0xeb]);
    let mut packets = VecDeque::from([
        Vec::new(),
        RESET_PACKET[..39].to_vec(),
        unrelated.to_vec(),
        non_reset.to_vec(),
        RESET_PACKET.to_vec(),
    ]);
    let deadline = Deadline::now() + Duration::from_secs(1);
    let reads = Cell::new(0);
    let mut receive = |passed_deadline| {
        assert_eq!(passed_deadline, deadline);
        reads.set(reads.get() + 1);
        ready(Ok(packets
            .pop_front()
            .expect("Read past the matching reset")))
    };

    let (status, reply) = wait_for_ack_reply(&probe, deadline, &mut receive)
        .await
        .unwrap();

    assert_eq!(reads.get(), 5);
    assert_eq!(status, PortStatus::Unfiltered);
    assert_eq!(reply.sequence_number, probe.acknowledgment_number);
}

#[tokio::test]
async fn receive_loop_times_out_a_receiver_that_never_completes() {
    let (probe, _, _) = matching_reset();
    let deadline = Deadline::now() + Duration::from_millis(20);
    let reads = Cell::new(0);
    let mut receive = |passed_deadline| {
        assert_eq!(passed_deadline, deadline);
        reads.set(reads.get() + 1);
        pending::<io::Result<Vec<u8>>>()
    };

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_ack_reply(&probe, deadline, &mut receive),
    )
    .await
    .expect("A pending receive must be bounded by the probe deadline")
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(reads.get(), 1);
    assert!(Deadline::now() >= deadline);
}

#[tokio::test]
async fn receive_loop_does_not_call_the_receiver_after_an_expired_deadline() {
    let (probe, _, _) = matching_reset();
    let deadline = Deadline::now();
    let mut receive = |_| -> std::future::Ready<io::Result<Vec<u8>>> {
        panic!("An expired probe must not start receiving, even a matching reset")
    };

    let error = wait_for_ack_reply(&probe, deadline, &mut receive)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[tokio::test]
async fn receive_loop_preserves_io_errors_after_discarding_a_packet() {
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::ConnectionReset,
        ErrorKind::TimedOut,
    ] {
        let (probe, _, _) = matching_reset();
        let deadline = Deadline::now() + Duration::from_secs(1);
        let reads = Cell::new(0);
        let mut receive = |passed_deadline| {
            assert_eq!(passed_deadline, deadline);
            reads.set(reads.get() + 1);
            ready(if reads.get() == 1 {
                Ok(Vec::new())
            } else {
                Err(io::Error::new(kind, "fixture receive failure"))
            })
        };

        let error = wait_for_ack_reply(&probe, deadline, &mut receive)
            .await
            .unwrap_err();

        assert_eq!(reads.get(), 2);
        assert_eq!(error.kind(), kind);
        assert_eq!(error.to_string(), "fixture receive failure");
    }
}

#[tokio::test]
async fn receive_loop_does_not_extend_the_deadline_for_continuous_invalid_packets() {
    let (probe, _, _) = matching_reset();
    let deadline = Deadline::now() + Duration::from_millis(20);
    let reads = Cell::new(0);
    let mut receive = |passed_deadline| {
        assert_eq!(passed_deadline, deadline);
        reads.set(reads.get() + 1);
        ready(Ok(vec![0; 3]))
    };

    let error = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_ack_reply(&probe, deadline, &mut receive),
    )
    .await
    .expect("Discarded packets must not keep the probe alive indefinitely")
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(reads.get() > 0);
    assert!(Deadline::now() >= deadline);
}

#[tokio::test]
async fn receive_loop_yields_to_other_futures_after_discarding_a_packet() {
    let (probe, _, _) = matching_reset();
    let deadline = Deadline::now() + Duration::from_secs(1);
    let other_future_ran = Cell::new(false);
    let reads = Cell::new(0);
    let mut receive = |_| {
        reads.set(reads.get() + 1);
        ready(Ok(if other_future_ran.get() {
            RESET_PACKET.to_vec()
        } else {
            Vec::new()
        }))
    };

    let (result, ()) = tokio::join!(
        biased;
        wait_for_ack_reply(&probe, deadline, &mut receive),
        async { other_future_ran.set(true) },
    );

    assert_eq!(result.unwrap().0, PortStatus::Unfiltered);
    assert_eq!(reads.get(), 2);
}

fn assert_no_application_evidence(result: &ScanResult) {
    assert!(result.service.is_none());
    assert!(result.banner.is_none());
    assert!(result.service_information.is_none());
    assert!(result.rpc_mappings.is_none());
}

#[tokio::test]
async fn finished_probe_records_reset_as_unfiltered_without_application_evidence() {
    let (probe, _, _) = matching_reset();
    let started = Instant::now();
    let deadline = Deadline::now() + Duration::from_secs(1);
    let result = finish_ack_probe(&probe, started, deadline, |passed_deadline| {
        assert_eq!(passed_deadline, deadline);
        ready(Ok(RESET_PACKET.to_vec()))
    })
    .await
    .unwrap();

    assert_eq!(result.port, probe.destination.port());
    assert_eq!(result.transport, ScanMode::Tcp);
    assert_eq!(result.status, PortStatus::Unfiltered);
    assert!(result.error.is_none());
    let observation = result.observation.as_deref().unwrap();
    assert!(observation.contains("Matching TCP RST"));
    assert!(observation.contains("service state is undetermined"));
    assert!(result.elapsed <= started.elapsed());
    assert_no_application_evidence(&result);
}

#[tokio::test]
async fn finished_probe_records_silence_as_tentative_filtering() {
    let (probe, _, _) = matching_reset();
    let started = Instant::now();
    let deadline = Deadline::now() + Duration::from_millis(20);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        finish_ack_probe(&probe, started, deadline, |_| {
            pending::<io::Result<Vec<u8>>>()
        }),
    )
    .await
    .expect("Result handling must keep the receive deadline")
    .unwrap();

    assert_eq!(result.port, probe.destination.port());
    assert_eq!(result.transport, ScanMode::Tcp);
    assert_eq!(result.status, PortStatus::Filtered);
    let error = result.error.as_deref().unwrap();
    assert!(error.contains("timed out"));
    assert!(error.contains("filtering is unconfirmed"));
    assert!(result.observation.is_none());
    assert!(result.elapsed >= Duration::from_millis(20));
    assert!(result.elapsed <= started.elapsed());
    assert_no_application_evidence(&result);
}

#[tokio::test]
async fn finished_probe_preserves_a_receiver_timeout_without_starting_another_receive() {
    let (probe, _, _) = matching_reset();
    let reads = Cell::new(0);
    let result = finish_ack_probe(
        &probe,
        Instant::now(),
        Deadline::now() + Duration::from_secs(1),
        |_| {
            reads.set(reads.get() + 1);
            ready(Err(io::Error::new(
                ErrorKind::TimedOut,
                "fixture receiver timeout",
            )))
        },
    )
    .await
    .unwrap();

    assert_eq!(reads.get(), 1);
    assert_eq!(result.status, PortStatus::Filtered);
    let error = result.error.as_deref().unwrap();
    assert!(error.contains("fixture receiver timeout"));
    assert!(error.contains("filtering is unconfirmed"));
    assert_no_application_evidence(&result);
}

#[tokio::test]
async fn finished_probe_keeps_local_io_failures_unknown_and_preserves_the_error() {
    for kind in [ErrorKind::PermissionDenied, ErrorKind::ConnectionReset] {
        let (probe, _, _) = matching_reset();
        let result = finish_ack_probe(
            &probe,
            Instant::now(),
            Deadline::now() + Duration::from_secs(1),
            |_| ready(Err(io::Error::new(kind, "fixture local failure"))),
        )
        .await
        .unwrap();

        assert_eq!(result.port, probe.destination.port());
        assert_eq!(result.transport, ScanMode::Tcp);
        assert_eq!(result.status, PortStatus::Unknown);
        assert_eq!(
            result.error.as_deref(),
            Some("Raw TCP ACK receive failed: fixture local failure")
        );
        assert!(result.observation.is_none());
        assert_no_application_evidence(&result);
    }
}
