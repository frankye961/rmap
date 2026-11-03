use super::{
    append_u32, build_portmapper_dump_call, build_portmapper_null_call, decode_record_marker,
    exchange_rpc_stream, frame_rpc_record, is_rpc_candidate, parse_portmapper_dump_reply, probe,
    probe_dump, read_rpc_mapping, read_rpc_record, read_u32, record_marker, response_information,
    skip_rpc_verifier, validate_portmapper_null_reply, validate_rpc_reply_header,
    validate_rpc_success_reply,
};

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

// Program 100000, program version 2, TCP (6), port 111.
const RPC_MAPPING: [u8; 16] = [0, 1, 0x86, 0xa0, 0, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 111];

#[test]
fn reads_an_advertised_mapping_in_wire_order() {
    let mut offset = 0;
    assert_eq!(
        read_rpc_mapping(&RPC_MAPPING, &mut offset).unwrap(),
        crate::model::rpc::RpcMapping {
            program: 100000,
            program_version: 2,
            protocol: 6,
            port: 111,
        }
    );
    assert_eq!(offset, 16);
}

#[test]
fn reads_successive_mappings_from_a_nonzero_cursor() {
    let mut data = vec![0xaa; 3];
    data.extend_from_slice(&RPC_MAPPING);
    data.extend_from_slice(&RPC_MAPPING);
    let mut offset = 3;
    for expected_end in [19, 35] {
        assert_eq!(read_rpc_mapping(&data, &mut offset).unwrap().port, 111);
        assert_eq!(offset, expected_end);
    }
}

#[test]
fn incomplete_mapping_fields_leave_the_callers_cursor_unchanged() {
    for start in [0, 3] {
        for length in 0..16 {
            let mut data = vec![0xaa; start];
            data.extend_from_slice(&RPC_MAPPING[..length]);
            let mut offset = start;
            let error = read_rpc_mapping(&data, &mut offset).unwrap_err();
            let field = match length {
                0..=3 => "program number",
                4..=7 => "program version",
                8..=11 => "protocol number",
                _ => "port number",
            };
            assert!(error.contains(field), "length {length}: {error}");
            assert_eq!(offset, start);
        }
    }
}

#[test]
fn mapping_port_validation_rejects_zero_and_oversized_values_without_advancing() {
    for port in [0_u32, 65536, u32::MAX] {
        let mut mapping = RPC_MAPPING;
        mapping[12..16].copy_from_slice(&port.to_be_bytes());
        let mut offset = 0;
        let error = read_rpc_mapping(&mapping, &mut offset).unwrap_err();
        assert!(error.contains("out of range 1..=65535"));
        assert!(error.contains(&port.to_string()));
        assert_eq!(offset, 0);
    }
}

#[test]
fn mapping_preserves_tcp_udp_and_boundary_ports_as_u32_values() {
    for protocol in [6_u32, 17] {
        for port in [1_u32, 65535] {
            let mut mapping = RPC_MAPPING;
            mapping[8..12].copy_from_slice(&protocol.to_be_bytes());
            mapping[12..16].copy_from_slice(&port.to_be_bytes());
            let mut offset = 0;
            let parsed = read_rpc_mapping(&mapping, &mut offset).unwrap();
            assert_eq!(parsed.protocol, protocol);
            assert_eq!(parsed.port, port);
            assert_eq!(offset, 16);
        }
    }
}

#[test]
fn invalid_mapping_offsets_return_an_error_without_panicking_or_advancing() {
    for start in [16, 17, usize::MAX - 3, usize::MAX] {
        let mut offset = start;
        assert!(read_rpc_mapping(&RPC_MAPPING, &mut offset).is_err());
        assert_eq!(offset, start);
    }
}

// Independent accepted-reply header: XID 0x12345678, REPLY, MSG_ACCEPTED.
const ACCEPTED_REPLY_HEADER: [u8; 12] = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0, 0, 0, 0];

// Independent complete NULL reply: accepted header, empty AUTH_NONE verifier, SUCCESS.
const NULL_REPLY: [u8; 24] = [
    0x12, 0x34, 0x56, 0x78, // XID.
    0, 0, 0, 1, // REPLY.
    0, 0, 0, 0, // MSG_ACCEPTED.
    0, 0, 0, 0, // Verifier flavor.
    0, 0, 0, 0, // Verifier body length.
    0, 0, 0, 0, // SUCCESS.
];

// Accepted reply with one advertised TCP registration and a terminating false marker.
const DUMP_REPLY: [u8; 48] = [
    0x12, 0x34, 0x56, 0x78, // XID.
    0, 0, 0, 1, // REPLY.
    0, 0, 0, 0, // MSG_ACCEPTED.
    0, 0, 0, 0, // AUTH_NONE verifier.
    0, 0, 0, 0, // Empty verifier body.
    0, 0, 0, 0, // SUCCESS.
    0, 0, 0, 1, // Entry follows.
    0, 1, 0x86, 0xa0, // Program 100000.
    0, 0, 0, 2, // Program version.
    0, 0, 0, 6, // TCP.
    0, 0, 0, 111, // Advertised port.
    0, 0, 0, 0, // End of list.
];

#[test]
fn accepts_an_empty_dump_even_with_a_zero_entry_limit() {
    let mut reply = NULL_REPLY.to_vec();
    reply.extend_from_slice(&[0; 4]);
    for limit in [0, 1, 128] {
        assert_eq!(
            parse_portmapper_dump_reply(&reply, 0x12345678, limit),
            Ok(Vec::new())
        );
    }
}

#[test]
fn accepts_dump_lists_at_exactly_the_entry_limit() {
    let first = crate::model::rpc::RpcMapping {
        program: 100000,
        program_version: 2,
        protocol: 6,
        port: 111,
    };
    assert_eq!(
        parse_portmapper_dump_reply(&DUMP_REPLY, 0x12345678, 1),
        Ok(vec![first.clone()])
    );
    let mut reply = DUMP_REPLY[..44].to_vec();
    let mut second_wire = RPC_MAPPING;
    second_wire[8..12].copy_from_slice(&17_u32.to_be_bytes());
    second_wire[12..16].copy_from_slice(&2049_u32.to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 1]);
    reply.extend_from_slice(&second_wire);
    reply.extend_from_slice(&[0; 4]);
    let second = crate::model::rpc::RpcMapping {
        program: 100000,
        program_version: 2,
        protocol: 17,
        port: 2049,
    };
    assert_eq!(
        parse_portmapper_dump_reply(&reply, 0x12345678, 2),
        Ok(vec![first, second])
    );
}

#[test]
fn rejects_an_extra_entry_before_attempting_to_read_its_fields() {
    let mut reply = NULL_REPLY.to_vec();
    reply.extend_from_slice(&[0, 0, 0, 1]); // No entry bytes: limit must be checked first.
    let error = parse_portmapper_dump_reply(&reply, 0x12345678, 0).unwrap_err();
    assert!(error.contains("exceeded maximum of 0 entries"));

    let mut reply = DUMP_REPLY[..44].to_vec();
    reply.extend_from_slice(&[0, 0, 0, 1]);
    let error = parse_portmapper_dump_reply(&reply, 0x12345678, 1).unwrap_err();
    assert!(error.contains("exceeded maximum of 1 entries"));
}

#[test]
fn rejects_invalid_xdr_list_markers_before_and_after_entries() {
    for marker in [2_u32, u32::MAX] {
        for prefix in [&NULL_REPLY[..], &DUMP_REPLY[..44]] {
            let mut reply = prefix.to_vec();
            reply.extend_from_slice(&marker.to_be_bytes());
            let error = parse_portmapper_dump_reply(&reply, 0x12345678, 1).unwrap_err();
            assert!(error.contains("Unexpected RPC list marker"));
            assert!(error.contains(&marker.to_string()));
        }
    }
}

#[test]
fn rejects_all_dump_truncations_including_a_missing_final_terminator() {
    for length in 0..DUMP_REPLY.len() {
        assert!(
            parse_portmapper_dump_reply(&DUMP_REPLY[..length], 0x12345678, 1).is_err(),
            "accepted truncated reply of length {length}"
        );
    }
    let error = parse_portmapper_dump_reply(&DUMP_REPLY[..44], 0x12345678, 1).unwrap_err();
    assert!(error.contains("Incomplete RPC list marker"));
}

#[test]
fn rejects_trailing_bytes_after_empty_and_nonempty_dump_lists() {
    let mut empty = NULL_REPLY.to_vec();
    empty.extend_from_slice(&[0; 4]);
    for valid in [&empty[..], &DUMP_REPLY[..]] {
        for extra in [&[0_u8][..], &[0, 0, 0, 0][..], &[0xff, 0xaa][..]] {
            let mut reply = valid.to_vec();
            reply.extend_from_slice(extra);
            let error = parse_portmapper_dump_reply(&reply, 0x12345678, 1).unwrap_err();
            assert!(error.contains("Unexpected bytes after RPC DUMP list"));
        }
    }
}

#[test]
fn dump_parser_reuses_header_verifier_and_procedure_validation() {
    assert!(
        parse_portmapper_dump_reply(&DUMP_REPLY, 0x12345679, 1)
            .unwrap_err()
            .contains("transaction ID does not match")
    );
    for (index, value, message) in [
        (7, 0, "Expected RPC REPLY"),
        (11, 1, "Expected RPC MSG_ACCEPTED"),
        (23, 1, "RPC procedure did not succeed"),
    ] {
        let mut reply = DUMP_REPLY;
        reply[index] = value;
        assert!(
            parse_portmapper_dump_reply(&reply, 0x12345678, 1)
                .unwrap_err()
                .contains(message)
        );
    }
    let mut reply = DUMP_REPLY;
    reply[16..20].copy_from_slice(&401_u32.to_be_bytes());
    assert!(
        parse_portmapper_dump_reply(&reply, 0x12345678, 1)
            .unwrap_err()
            .contains("maximum of 400 bytes")
    );
}

#[test]
fn dump_parser_rejects_out_of_range_advertised_ports() {
    for port in [0_u32, 65536, u32::MAX] {
        let mut reply = DUMP_REPLY;
        reply[40..44].copy_from_slice(&port.to_be_bytes());
        assert!(
            parse_portmapper_dump_reply(&reply, 0x12345678, 1)
                .unwrap_err()
                .contains("out of range 1..=65535")
        );
    }
}

#[test]
fn shared_success_validation_leaves_procedure_payload_for_the_caller() {
    let mut reply = NULL_REPLY.to_vec();
    reply.extend_from_slice(&[0, 0, 0, 0]); // Empty DUMP-list terminator.
    assert_eq!(validate_rpc_success_reply(&reply, 0x12345678), Ok(24));
    assert!(validate_portmapper_null_reply(&reply, 0x12345678).is_err());

    let mut reply = ACCEPTED_REPLY_HEADER.to_vec();
    reply.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0xaa, 0, 0, 0]);
    reply.extend_from_slice(&[0; 8]); // SUCCESS, then empty-list terminator.
    assert_eq!(validate_rpc_success_reply(&reply, 0x12345678), Ok(28));
}

#[tokio::test]
async fn shared_stream_exchange_sends_null_and_dump_requests_before_reading() {
    for (call, expected_call, has_list) in [
        (
            build_portmapper_null_call(0x12345678),
            PORTMAPPER_NULL_CALL,
            false,
        ),
        (
            build_portmapper_dump_call(0x12345678),
            PORTMAPPER_DUMP_CALL,
            true,
        ),
    ] {
        let frame = frame_rpc_record(&call).unwrap();
        let mut reply = NULL_REPLY.to_vec();
        if has_list {
            reply.extend_from_slice(&[0; 4]);
        }
        let expected_reply = reply.clone();
        let (mut client, mut server) = tokio::io::duplex(8);
        let exchange = exchange_rpc_stream(
            &mut client,
            &frame,
            Instant::now() + Duration::from_secs(1),
            4096,
        );
        let serve = async move {
            let mut request = [0; 44];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[0x80, 0, 0, 40]);
            assert_eq!(&request[4..], &expected_call);
            let marker = 0x80000000_u32 | reply.len() as u32;
            server.write_all(&marker.to_be_bytes()).await.unwrap();
            server.write_all(&reply).await.unwrap();
        };
        let (received, ()) = tokio::join!(exchange, serve);
        assert_eq!(received.unwrap(), expected_reply);
    }
}

#[tokio::test]
async fn shared_exchange_reports_write_failure_before_attempting_a_read() {
    let (mut client, server) = tokio::io::duplex(8);
    drop(server);
    let frame = frame_rpc_record(&PORTMAPPER_NULL_CALL).unwrap();
    let error = exchange_rpc_stream(
        &mut client,
        &frame,
        Instant::now() + Duration::from_secs(1),
        4096,
    )
    .await
    .unwrap_err();
    assert!(error.contains("Failed to write RPC request"));
}

#[tokio::test]
async fn shared_exchange_bounds_a_blocked_request_write() {
    let (mut client, server) = tokio::io::duplex(1);
    let frame = frame_rpc_record(&PORTMAPPER_DUMP_CALL).unwrap();
    let error = exchange_rpc_stream(
        &mut client,
        &frame,
        Instant::now() + Duration::from_millis(20),
        4096,
    )
    .await
    .unwrap_err();
    assert!(error.contains("RPC request writing timed out"));
    drop(server);
}

#[tokio::test]
async fn dump_probe_rejects_an_expired_deadline_before_connecting() {
    let error = probe_dump("192.0.2.1:111".parse().unwrap(), 1, Instant::now(), 4096)
        .await
        .unwrap_err();
    assert!(error.contains("RPC connection timed out"));
}

// An in-memory reader that deliberately returns at most one byte per read.
struct OneByteReads<'a>(&'a [u8]);

impl AsyncRead for OneByteReads<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() > 0
            && let Some((&byte, rest)) = self.0.split_first()
        {
            buffer.put_slice(&[byte]);
            self.0 = rest;
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn expired_probe_deadline_returns_before_attempting_a_connection() {
    // The expired deadline must trigger the guard before TcpStream::connect.
    let target = "192.0.2.1:111".parse().unwrap();
    let result = probe(target, 0x12345678, Instant::now(), 4096).await;
    assert_eq!(result, Err("RPC connection timed out".to_string()));
}

#[tokio::test]
async fn reads_one_record_without_consuming_the_following_record() {
    let mut wire = vec![0x80, 0, 0, 24];
    wire.extend_from_slice(&NULL_REPLY);
    wire.extend_from_slice(&[0x80, 0, 0, 0]);
    let mut reader = wire.as_slice();
    let payload = read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 24)
        .await
        .unwrap();
    assert_eq!(payload, NULL_REPLY);
    assert_eq!(reader, &[0x80, 0, 0, 0]);
    assert!(response_information(&payload, 0x12345678).is_ok());
}

#[tokio::test]
async fn assembles_fragments_across_short_reads_and_empty_nonfinal_fragments() {
    let mut wire = vec![0, 0, 0, 0, 0, 0, 0, 10];
    wire.extend_from_slice(&NULL_REPLY[..10]);
    wire.extend_from_slice(&[0, 0, 0, 0, 0x80, 0, 0, 14]);
    wire.extend_from_slice(&NULL_REPLY[10..]);
    let mut reader = OneByteReads(&wire);
    let payload = read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 24)
        .await
        .unwrap();
    assert_eq!(payload, NULL_REPLY);
    assert!(reader.0.is_empty());
}

#[tokio::test]
async fn accepts_a_zero_length_final_record_with_a_zero_byte_limit() {
    let mut reader = &[0x80, 0, 0, 0][..];
    assert_eq!(
        read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 0).await,
        Ok(Vec::new())
    );
}

#[tokio::test]
async fn rejects_premature_eof_in_markers_and_fragment_payloads() {
    for length in 0..4 {
        let mut reader = &[0x80, 0, 0, 24][..length];
        let error = read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 24)
            .await
            .unwrap_err();
        assert!(error.contains("Failed to read RPC record marker"));
    }
    for length in 0..NULL_REPLY.len() {
        let mut wire = vec![0x80, 0, 0, 24];
        wire.extend_from_slice(&NULL_REPLY[..length]);
        let mut reader = wire.as_slice();
        let error = read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 24)
            .await
            .unwrap_err();
        assert!(error.contains("Failed to read RPC fragment"));
    }
}

#[tokio::test]
async fn rejects_oversized_fragments_before_reading_or_allocating_their_payload() {
    // The maximum representable length must fail the limit check, not attempt a huge read.
    let mut reader = &[0xff, 0xff, 0xff, 0xff][..];
    let error = read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 24)
        .await
        .unwrap_err();
    assert!(error.contains("maximum allowed payload of 24 bytes"));

    let mut reader = &[0, 0, 0, 2, 0xaa, 0xbb, 0x80, 0, 0, 3, 0xcc, 0xdd, 0xee][..];
    let error = read_rpc_record(&mut reader, Instant::now() + Duration::from_secs(1), 4)
        .await
        .unwrap_err();
    assert!(error.contains("maximum allowed payload of 4 bytes"));
    assert_eq!(reader, &[0xcc, 0xdd, 0xee]);
}

#[tokio::test]
async fn rejects_an_expired_deadline_even_when_empty_fragments_are_ready() {
    let bytes = [0, 0, 0, 0, 0x80, 0, 0, 0];
    let mut reader = bytes.as_slice();
    let error = read_rpc_record(&mut reader, Instant::now(), 24)
        .await
        .unwrap_err();
    assert!(error.contains("timed out"));
    assert_eq!(reader, bytes.as_slice());
}

#[tokio::test]
async fn times_out_when_a_marker_is_incomplete_but_the_stream_stays_open() {
    let (mut reader, mut writer) = tokio::io::duplex(16);
    writer.write_all(&[0x80, 0]).await.unwrap();
    let error = read_rpc_record(&mut reader, Instant::now() + Duration::from_millis(20), 24)
        .await
        .unwrap_err();
    assert!(error.contains("RPC record reading timed out"));
    drop(writer);
}

#[tokio::test]
async fn times_out_when_a_fragment_is_incomplete_but_the_stream_stays_open() {
    let (mut reader, mut writer) = tokio::io::duplex(16);
    writer.write_all(&[0x80, 0, 0, 3, 0xaa]).await.unwrap();
    let error = read_rpc_record(&mut reader, Instant::now() + Duration::from_millis(20), 24)
        .await
        .unwrap_err();
    assert!(error.contains("RPC fragment reading timed out"));
    drop(writer);
}

#[test]
fn decodes_record_markers_in_network_byte_order_and_separates_the_final_flag() {
    for (marker, expected) in [
        ([0x80, 0, 0, 0x18], (true, 24)),
        ([0, 0, 0, 0x18], (false, 24)),
        ([0x81, 0x23, 0x45, 0x67], (true, 0x01234567)),
        ([0x01, 0x23, 0x45, 0x67], (false, 0x01234567)),
    ] {
        assert_eq!(decode_record_marker(&marker), Ok(expected));
    }
}

#[test]
fn decodes_empty_and_maximum_length_fragments_without_allocating_payloads() {
    for (marker, expected) in [
        ([0, 0, 0, 0], (false, 0)),
        ([0x80, 0, 0, 0], (true, 0)),
        ([0x7f, 0xff, 0xff, 0xff], (false, 0x7fffffff)),
        ([0xff, 0xff, 0xff, 0xff], (true, 0x7fffffff)),
    ] {
        assert_eq!(decode_record_marker(&marker), Ok(expected));
    }
}

#[test]
fn rejects_record_markers_shorter_or_longer_than_four_bytes() {
    for length in [0, 1, 2, 3, 5, 6, 7, 8] {
        let error = decode_record_marker(&[0; 8][..length]).unwrap_err();
        assert!(error.contains("exactly 4 bytes"));
    }
}

#[test]
fn selects_only_port_111_as_the_initial_rpc_candidate() {
    for port in 0..=u16::MAX {
        assert_eq!(is_rpc_candidate(port), port == 111);
    }
}

#[test]
fn maps_only_a_validated_reply_without_guessing_software_identity() {
    let information = response_information(&NULL_REPLY, 0x12345678).unwrap();
    assert_eq!(information.transport, crate::model::ScanMode::Tcp);
    assert_eq!(information.service.as_deref(), Some("rpcbind"));
    assert!(information.product.is_none());
    assert!(information.version.is_none());
    let observation = information.observation.as_deref().unwrap();
    assert!(observation.contains("100000"));
    assert!(observation.contains("protocol version 2"));
    assert!(observation.contains("NULL procedure succeeded"));

    assert!(response_information(&[], 0x12345678).is_err());
    assert!(response_information(&NULL_REPLY, 0x12345679).is_err());
    let mut unsuccessful = NULL_REPLY;
    unsuccessful[23] = 1;
    assert!(response_information(&unsuccessful, 0x12345678).is_err());
}

#[test]
fn accepts_complete_null_replies_with_empty_and_padded_verifiers() {
    assert_eq!(
        validate_portmapper_null_reply(&NULL_REPLY, 0x12345678),
        Ok(())
    );
    let mut reply = ACCEPTED_REPLY_HEADER.to_vec();
    // Flavor 1, one opaque body byte, three padding bytes, SUCCESS.
    reply.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0xab, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(validate_portmapper_null_reply(&reply, 0x12345678), Ok(()));
}

#[test]
fn rejects_every_truncation_of_a_complete_null_reply() {
    for length in 0..NULL_REPLY.len() {
        assert!(
            validate_portmapper_null_reply(&NULL_REPLY[..length], 0x12345678).is_err(),
            "accepted truncated reply of length {length}"
        );
    }
    let error = validate_portmapper_null_reply(&NULL_REPLY[..23], 0x12345678).unwrap_err();
    assert!(error.contains("Incomplete RPC procedure status"));
}

#[test]
fn rejects_procedure_errors_even_when_the_rpc_header_was_accepted() {
    for status in [1_u32, 2, 3, 4, 5, u32::MAX] {
        let mut reply = NULL_REPLY;
        reply[20..24].copy_from_slice(&status.to_be_bytes());
        let error = validate_portmapper_null_reply(&reply, 0x12345678).unwrap_err();
        assert!(error.contains("RPC procedure did not succeed"));
        assert!(error.contains(&format!("accept status {status}")));
    }
}

#[test]
fn null_reply_validation_propagates_header_errors() {
    let error = validate_portmapper_null_reply(&NULL_REPLY, 0x12345679).unwrap_err();
    assert!(error.contains("transaction ID does not match"));
    for (position, value, expected) in [(7, 0, "REPLY"), (11, 1, "MSG_ACCEPTED")] {
        let mut reply = NULL_REPLY;
        reply[position] = value;
        let error = validate_portmapper_null_reply(&reply, 0x12345678).unwrap_err();
        assert!(error.contains(expected));
    }
}

#[test]
fn null_reply_validation_propagates_verifier_errors() {
    let mut reply = NULL_REPLY;
    reply[16..20].copy_from_slice(&401_u32.to_be_bytes());
    let error = validate_portmapper_null_reply(&reply, 0x12345678).unwrap_err();
    assert!(error.contains("maximum of 400 bytes"));

    let mut reply = ACCEPTED_REPLY_HEADER.to_vec();
    reply.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0xab, 0, 1, 0, 0, 0, 0, 0]);
    let error = validate_portmapper_null_reply(&reply, 0x12345678).unwrap_err();
    assert!(error.contains("padding must contain only zero bytes"));
}

#[test]
fn rejects_unexpected_payload_after_a_successful_null_reply() {
    for extra in [&[0_u8][..], &[0, 0, 0, 0][..], &[0xff, 0xaa][..]] {
        let mut reply = NULL_REPLY.to_vec();
        reply.extend_from_slice(extra);
        let error = validate_portmapper_null_reply(&reply, 0x12345678).unwrap_err();
        assert!(error.contains("Unexpected bytes after RPC NULL reply"));
    }
}

#[test]
fn skips_an_empty_verifier_without_consuming_the_following_status() {
    let mut reply = ACCEPTED_REPLY_HEADER.to_vec();
    reply.extend_from_slice(&[0; 8]); // AUTH_NONE and empty body.
    reply.extend_from_slice(&[0, 0, 0, 5]); // Following procedure status.
    let mut offset = skip_rpc_verifier(&reply, 12).unwrap();
    assert_eq!(offset, 20);
    assert_eq!(read_u32(&reply, &mut offset), Some(5));
}

#[test]
fn skips_opaque_bodies_with_each_padding_length() {
    for (body_len, padding_len) in [(1_u32, 3), (2, 2), (3, 1), (4, 0), (5, 3), (8, 0)] {
        let mut verifier = vec![0, 0, 0, 1]; // Flavor, structurally parsed only.
        verifier.extend_from_slice(&body_len.to_be_bytes());
        verifier.extend(vec![0xab; body_len as usize]);
        verifier.extend(vec![0; padding_len]);
        let expected_end = verifier.len();
        verifier.extend_from_slice(&[0xff; 4]); // Must not be consumed as padding.
        assert_eq!(skip_rpc_verifier(&verifier, 0), Ok(expected_end));
    }
}

#[test]
fn accepts_a_complete_400_byte_verifier_body() {
    let mut verifier = vec![0, 0, 0, 1, 0, 0, 1, 0x90];
    verifier.extend_from_slice(&[0xab; 400]);
    assert_eq!(skip_rpc_verifier(&verifier, 0), Ok(408));
}

#[test]
fn rejects_oversized_verifier_lengths_before_reading_the_body() {
    for length in [401_u32, u32::MAX] {
        let mut verifier = vec![0; 4];
        verifier.extend_from_slice(&length.to_be_bytes());
        let error = skip_rpc_verifier(&verifier, 0).unwrap_err();
        assert!(error.contains("maximum of 400 bytes"));
        assert!(error.contains(&length.to_string()));
    }
}

#[test]
fn rejects_every_truncation_of_verifier_fields_body_and_padding() {
    // Flavor 1, five body bytes, three zero padding bytes.
    let verifier = [
        0, 0, 0, 1, 0, 0, 0, 5, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0, 0, 0,
    ];
    for length in 0..verifier.len() {
        let error = skip_rpc_verifier(&verifier[..length], 0).unwrap_err();
        let field = match length {
            0..=3 => "verifier flavor",
            4..=7 => "verifier body length",
            8..=12 => "verifier body",
            _ => "verifier padding",
        };
        assert!(error.contains(field), "length {length}: {error}");
    }
}

#[test]
fn rejects_nonzero_bytes_at_every_padding_position() {
    for position in 9..12 {
        let mut verifier = [0, 0, 0, 1, 0, 0, 0, 1, 0xab, 0, 0, 0];
        verifier[position] = 1;
        let error = skip_rpc_verifier(&verifier, 0).unwrap_err();
        assert!(error.contains("padding must contain only zero bytes"));
    }
}

#[test]
fn rejects_out_of_bounds_and_overflowing_verifier_offsets_without_panicking() {
    for offset in [9, usize::MAX - 3, usize::MAX - 1, usize::MAX] {
        assert!(skip_rpc_verifier(&[0; 8], offset).is_err());
    }
}

#[test]
fn accepts_matching_reply_header_and_returns_the_next_position() {
    assert_eq!(
        validate_rpc_reply_header(&ACCEPTED_REPLY_HEADER, 0x12345678),
        Ok(12)
    );
    let mut message = ACCEPTED_REPLY_HEADER.to_vec();
    message.extend_from_slice(&[0xff; 12]);
    assert_eq!(validate_rpc_reply_header(&message, 0x12345678), Ok(12));
}

#[test]
fn rejects_every_truncated_reply_header_with_the_incomplete_field_name() {
    for length in 0..12 {
        let error =
            validate_rpc_reply_header(&ACCEPTED_REPLY_HEADER[..length], 0x12345678).unwrap_err();
        let field = match length {
            0..=3 => "transaction ID",
            4..=7 => "message type",
            _ => "reply status",
        };
        assert!(error.contains(field), "length {length}: {error}");
    }
}

#[test]
fn rejects_a_reply_for_a_different_transaction() {
    let error = validate_rpc_reply_header(&ACCEPTED_REPLY_HEADER, 0x12345679).unwrap_err();
    assert!(error.contains("transaction ID does not match"));
}

#[test]
fn rejects_call_and_unknown_message_types() {
    for message_type in [0_u32, 2, u32::MAX] {
        let mut header = ACCEPTED_REPLY_HEADER;
        header[4..8].copy_from_slice(&message_type.to_be_bytes());
        let error = validate_rpc_reply_header(&header, 0x12345678).unwrap_err();
        assert!(error.contains("Expected RPC REPLY (1)"));
        assert!(error.contains(&format!("received message type {message_type}")));
    }
}

#[test]
fn rejects_denied_and_unknown_reply_statuses() {
    for status in [1_u32, 2, u32::MAX] {
        let mut header = ACCEPTED_REPLY_HEADER;
        header[8..12].copy_from_slice(&status.to_be_bytes());
        let error = validate_rpc_reply_header(&header, 0x12345678).unwrap_err();
        assert!(error.contains("Expected RPC MSG_ACCEPTED (0)"));
        assert!(error.contains(&format!("received reply status {status}")));
    }
}

#[test]
fn reads_big_endian_integer_and_advances_by_four_bytes() {
    let mut offset = 0;
    assert_eq!(
        read_u32(&[0x12, 0x34, 0x56, 0x78], &mut offset),
        Some(0x12345678)
    );
    assert_eq!(offset, 4);
}

#[test]
fn reads_sequential_fields_from_a_nonzero_offset() {
    let data = [0xaa, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xff];
    let mut offset = 1;
    assert_eq!(read_u32(&data, &mut offset), Some(0x12345678));
    assert_eq!(offset, 5);
    assert_eq!(read_u32(&data, &mut offset), Some(0x90abcdef));
    assert_eq!(offset, 9);
    assert_eq!(read_u32(&data, &mut offset), None);
    assert_eq!(offset, 9);
}

#[test]
fn reads_zero_one_high_bit_and_maximum_as_unsigned_values() {
    for (data, expected) in [
        ([0, 0, 0, 0], 0),
        ([0, 0, 0, 1], 1),
        ([0x80, 0, 0, 0], 0x80000000),
        ([0xff, 0xff, 0xff, 0xff], u32::MAX),
    ] {
        let mut offset = 0;
        assert_eq!(read_u32(&data, &mut offset), Some(expected));
        assert_eq!(offset, 4);
    }
}

#[test]
fn truncated_and_out_of_bounds_reads_leave_the_cursor_unchanged() {
    let data = [0x12, 0x34, 0x56, 0x78];
    for length in 0..4 {
        let mut offset = 0;
        assert_eq!(read_u32(&data[..length], &mut offset), None);
        assert_eq!(offset, 0);
    }
    for start in 1..=5 {
        let mut offset = start;
        assert_eq!(read_u32(&data, &mut offset), None);
        assert_eq!(offset, start);
    }
}

#[test]
fn overflowing_cursor_does_not_panic_or_advance() {
    for start in [usize::MAX, usize::MAX - 1, usize::MAX - 2, usize::MAX - 3] {
        let mut offset = start;
        assert_eq!(read_u32(&[0; 4], &mut offset), None);
        assert_eq!(offset, start);
    }
}

#[test]
fn reads_every_field_of_the_independent_rpc_call_fixture() {
    let mut offset = 0;
    for value in [0x12345678, 0, 2, 100000, 2, 0, 0, 0, 0, 0] {
        assert_eq!(read_u32(&PORTMAPPER_NULL_CALL, &mut offset), Some(value));
    }
    assert_eq!(offset, 40);
    assert_eq!(read_u32(&PORTMAPPER_NULL_CALL, &mut offset), None);
    assert_eq!(offset, 40);
}

#[test]
fn frames_a_small_payload_with_its_length_excluding_the_marker() {
    let message = [0xaa, 0xbb, 0xcc];
    let frame = frame_rpc_record(&message).unwrap();
    assert_eq!(frame, [0x80, 0, 0, 3, 0xaa, 0xbb, 0xcc]);
}

#[test]
fn frames_an_empty_fragment_with_a_zero_data_length() {
    assert_eq!(frame_rpc_record(&[]).unwrap(), [0x80, 0, 0, 0]);
}

#[test]
fn frames_a_multibyte_length_and_preserves_all_payload_bytes() {
    let message: Vec<u8> = (0..=u8::MAX).collect();
    let frame = frame_rpc_record(&message).unwrap();
    assert_eq!(frame.len(), 260);
    assert_eq!(&frame[..4], &[0x80, 0, 1, 0]);
    assert_eq!(&frame[4..], message.as_slice());
}

#[test]
fn combines_the_null_call_and_marker_into_a_44_byte_frame() {
    let call = build_portmapper_null_call(0x12345678);
    let frame = frame_rpc_record(&call).unwrap();
    assert_eq!(frame.len(), 44);
    assert_eq!(&frame[..4], &[0x80, 0, 0, 0x28]);
    assert_eq!(&frame[4..], &PORTMAPPER_NULL_CALL);
    assert_eq!(call, PORTMAPPER_NULL_CALL);
}

#[test]
fn marker_sets_the_final_fragment_bit_and_preserves_small_lengths() {
    for (length, expected) in [
        (0, 0x80000000),
        (1, 0x80000001),
        (40, 0x80000028),
        (255, 0x800000ff),
        (256, 0x80000100),
    ] {
        assert_eq!(record_marker(length).unwrap(), expected);
    }
    assert_eq!(record_marker(40).unwrap().to_be_bytes(), [0x80, 0, 0, 0x28]);
}

#[test]
fn marker_accepts_the_largest_31_bit_fragment() {
    assert_eq!(record_marker(0x7fff_ffff).unwrap(), u32::MAX);
}

#[test]
fn marker_rejects_oversized_lengths_before_truncation_without_allocating() {
    for length in [0x8000_0000, usize::MAX] {
        let error = record_marker(length).unwrap_err();
        assert!(error.contains(&length.to_string()));
        assert!(error.contains("31-bit maximum"));
    }
}

// Independent wire fixture: XID 0x12345678, CALL, RPC v2, portmapper v2,
// procedure NULL, empty AUTH_NONE credentials and verifier. No TCP record marker.
const PORTMAPPER_NULL_CALL: [u8; 40] = [
    0x12, 0x34, 0x56, 0x78, // Transaction identifier.
    0x00, 0x00, 0x00, 0x00, // CALL.
    0x00, 0x00, 0x00, 0x02, // RPC protocol version.
    0x00, 0x01, 0x86, 0xa0, // Program 100000.
    0x00, 0x00, 0x00, 0x02, // Portmapper program version.
    0x00, 0x00, 0x00, 0x00, // NULL procedure.
    0x00, 0x00, 0x00, 0x00, // Credential flavor: AUTH_NONE.
    0x00, 0x00, 0x00, 0x00, // Credential data length.
    0x00, 0x00, 0x00, 0x00, // Verifier flavor: AUTH_NONE.
    0x00, 0x00, 0x00, 0x00, // Verifier data length.
];

// Independent wire fixture: DUMP is procedure 4 on portmapper version 2.
const PORTMAPPER_DUMP_CALL: [u8; 40] = [
    0x12, 0x34, 0x56, 0x78, // XID.
    0, 0, 0, 0, // CALL.
    0, 0, 0, 2, // RPC protocol version.
    0, 1, 0x86, 0xa0, // Program 100000.
    0, 0, 0, 2, // Portmapper program version.
    0, 0, 0, 4, // DUMP procedure.
    0, 0, 0, 0, // Credential flavor: AUTH_NONE.
    0, 0, 0, 0, // Credential body length.
    0, 0, 0, 0, // Verifier flavor: AUTH_NONE.
    0, 0, 0, 0, // Verifier body length.
];

#[test]
fn builds_the_complete_dump_request_using_portmapper_version_two() {
    assert_eq!(build_portmapper_dump_call(0x12345678), PORTMAPPER_DUMP_CALL);
}

#[test]
fn dump_transaction_id_changes_only_the_first_four_bytes() {
    for xid in [0_u32, 1, 0x80000000, u32::MAX] {
        let call = build_portmapper_dump_call(xid);
        assert_eq!(call.len(), 40);
        assert_eq!(&call[..4], &xid.to_be_bytes());
        assert_eq!(&call[4..], &PORTMAPPER_DUMP_CALL[4..]);
    }
}

#[test]
fn frames_the_dump_request_without_changing_its_procedure_or_null_behavior() {
    let call = build_portmapper_dump_call(0x12345678);
    let frame = frame_rpc_record(&call).unwrap();
    assert_eq!(frame.len(), 44);
    assert_eq!(&frame[..4], &[0x80, 0, 0, 40]);
    assert_eq!(&frame[4..], &PORTMAPPER_DUMP_CALL);
    assert_eq!(build_portmapper_null_call(0x12345678), PORTMAPPER_NULL_CALL);
}

#[test]
fn builds_the_complete_portmapper_null_call_in_wire_order() {
    assert_eq!(build_portmapper_null_call(0x12345678), PORTMAPPER_NULL_CALL);
}

#[test]
fn transaction_id_changes_only_the_first_four_bytes() {
    for (xid, expected) in [
        (0, [0x00, 0x00, 0x00, 0x00]),
        (1, [0x00, 0x00, 0x00, 0x01]),
        (0x80000000, [0x80, 0x00, 0x00, 0x00]),
        (u32::MAX, [0xff, 0xff, 0xff, 0xff]),
    ] {
        let call = build_portmapper_null_call(xid);
        assert_eq!(call.len(), 40);
        assert_eq!(&call[..4], &expected);
        assert_eq!(&call[4..], &PORTMAPPER_NULL_CALL[4..]);
    }
}

#[test]
fn appends_four_bytes_in_network_byte_order() {
    let mut buffer = Vec::new();
    append_u32(&mut buffer, 0x12345678);
    assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn encodes_zero_one_high_bit_and_maximum_without_losing_bytes() {
    for (value, expected) in [
        (0, [0x00, 0x00, 0x00, 0x00]),
        (1, [0x00, 0x00, 0x00, 0x01]),
        (0x80000000, [0x80, 0x00, 0x00, 0x00]),
        (u32::MAX, [0xff, 0xff, 0xff, 0xff]),
    ] {
        let mut buffer = Vec::new();
        append_u32(&mut buffer, value);
        assert_eq!(buffer, expected, "incorrect encoding for {value:#010x}");
    }
}

#[test]
fn preserves_existing_contents_when_appending() {
    let mut buffer = vec![0xaa, 0xbb];
    append_u32(&mut buffer, 0x12345678);
    assert_eq!(buffer, [0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn repeated_appends_preserve_field_order() {
    let mut buffer = Vec::new();
    append_u32(&mut buffer, 0x12345678);
    append_u32(&mut buffer, 0x90abcdef);
    assert_eq!(buffer, [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
}
