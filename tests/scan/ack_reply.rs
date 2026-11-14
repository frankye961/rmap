//! Parsed packet fixtures for ACK correlation; no sockets or live probes.

use std::net::{Ipv4Addr, SocketAddrV4};

use super::match_ack_reply;
use crate::model::syn::{ParsedIpv4Packet, TcpReply};
use crate::scan::ack::AckProbe;

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
