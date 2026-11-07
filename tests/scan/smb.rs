use super::{
    build_smb_negotiate_request, build_smb2_negotiate_request_body,
    build_smb2_negotiate_request_header, encode_smb2_header, encode_smb2_request,
    exchange_smb_stream, frame_smb_message, is_smb_candidate, probe, read_smb_message,
    response_information,
};
use crate::model::ScanMode;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf, duplex};
use tokio::time::Instant;

const MESSAGE_ID: u64 = 0x1122_3344_5566_7788;

// Independent SMB2 response fixture, excluding the Direct TCP prefix.
// Nonzero granted credits distinguish bytes 14..16 from the status at 8..12.
fn negotiate_reply(dialect: u16) -> Vec<u8> {
    let mut reply = vec![0; 128];
    reply[..32].copy_from_slice(&[
        0xfe, 0x53, 0x4d, 0x42, // Protocol ID.
        0x40, 0, 0, 0, // Header size and credit charge.
        0, 0, 0, 0, // Success status.
        0, 0, 7, 0, // NEGOTIATE command and granted credits.
        1, 0, 0, 0, // Server response flag.
        0, 0, 0, 0, // No next command.
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Message ID.
    ]);
    reply[64..72].copy_from_slice(&[65, 0, 1, 0, 2, 2, 0, 0]);
    reply[68..70].copy_from_slice(&dialect.to_le_bytes());
    // MaxTransactSize, MaxReadSize, and MaxWriteSize are each 65536.
    reply[92..104].copy_from_slice(&[0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0]);
    reply
}

#[test]
fn selects_only_the_initial_direct_tcp_candidate() {
    for (port, expected) in [
        (445, true),
        (0, false),
        (139, false),
        (444, false),
        (446, false),
    ] {
        assert_eq!(is_smb_candidate(port), expected);
    }
}

#[test]
fn request_preserves_caller_values_and_offers_only_the_initial_dialects() {
    let guid = [0xa5; 16];
    let request = build_smb_negotiate_request(MESSAGE_ID, guid).unwrap();
    assert_eq!(request.header.message_id, MESSAGE_ID);
    assert_eq!(request.header.command, 0);
    assert_eq!(request.header.flags, 0);
    assert_eq!(request.body.client_guid, guid);
    assert_eq!(request.body.dialect_count, 2);
    assert_eq!(request.body.dialects, [0x0202, 0x0210]);
    assert_eq!(request.body.structure_size, 36);
    assert_eq!(request.body.security_mode, 1);
}

#[test]
fn rejects_empty_and_oversized_dialect_lists_without_truncating_the_count() {
    let empty_error = build_smb2_negotiate_request_body(&[], [0; 16]).unwrap_err();
    assert!(empty_error.contains("at least one dialect"));
    let dialects = vec![0x0202; usize::from(u16::MAX) + 1];
    let error = build_smb2_negotiate_request_body(&dialects, [0; 16]).unwrap_err();
    assert!(error.contains("Too many dialects"));
    let body =
        build_smb2_negotiate_request_body(&dialects[..usize::from(u16::MAX)], [0; 16]).unwrap();
    assert_eq!(body.dialect_count, u16::MAX);
    assert_eq!(body.dialects.len(), usize::from(u16::MAX));
}

#[test]
fn header_encoding_matches_an_independent_64_byte_layout() {
    // Deliberately varied fields exercise encoding, not a valid negotiation policy.
    let mut header = build_smb2_negotiate_request_header(0x1516_1718_191a_1b1c).unwrap();
    header.credit_charge = 0x0304;
    header.channel_sequence = 0x0506;
    header.reserved = 0x0708;
    header.command = 0x090a;
    header.credit_request = 0x0b0c;
    header.flags = 0x0d0e_0f10;
    header.next_command = 0x1112_1314;
    header.reserved2 = 0x1d1e_1f20;
    header.tree_id = 0x2122_2324;
    header.session_id = 0x2526_2728_292a_2b2c;
    header.signature = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f,
    ];
    let expected: [u8; 64] = [
        0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07, 0x0a, 0x09, 0x0c,
        0x0b, 0x10, 0x0f, 0x0e, 0x0d, 0x14, 0x13, 0x12, 0x11, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17,
        0x16, 0x15, 0x20, 0x1f, 0x1e, 0x1d, 0x24, 0x23, 0x22, 0x21, 0x2c, 0x2b, 0x2a, 0x29, 0x28,
        0x27, 0x26, 0x25, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];
    assert_eq!(encode_smb2_header(&header).unwrap(), expected);
}

#[test]
fn header_encoding_retains_all_message_id_bits() {
    for id in [0, 1, MESSAGE_ID, u64::MAX] {
        let header = build_smb2_negotiate_request_header(id).unwrap();
        let encoded = encode_smb2_header(&header).unwrap();
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[24..32], &id.to_le_bytes());
    }
}

#[test]
fn frames_payload_without_modifying_it_or_counting_the_transport_header() {
    assert_eq!(frame_smb_message(&[]).unwrap(), [0, 0, 0, 0]);
    assert_eq!(
        frame_smb_message(&[0xfe, 0x53, 0x4d, 0x42]).unwrap(),
        [0, 0, 0, 4, 0xfe, 0x53, 0x4d, 0x42],
    );
}

#[test]
fn framing_handles_length_boundaries_and_the_exact_24_bit_maximum() {
    for (length, prefix) in [
        (255, [0, 0, 0, 255]),
        (256, [0, 0, 1, 0]),
        (65535, [0, 0, 255, 255]),
        (65536, [0, 1, 0, 0]),
        (0x00ff_ffff, [0, 255, 255, 255]),
    ] {
        let payload = vec![0xa5; length];
        let framed = frame_smb_message(&payload).unwrap();
        assert_eq!(&framed[..4], &prefix);
        assert_eq!(&framed[4..], payload.as_slice());
        assert_eq!(framed.len(), length + 4);
    }
    assert!(frame_smb_message(&vec![0; 0x0100_0000]).is_err());
}

#[test]
fn identifies_each_offered_dialect_without_guessing_software_or_os() {
    for dialect in [0x0202, 0x0210] {
        let information = response_information(&negotiate_reply(dialect), MESSAGE_ID).unwrap();
        assert_eq!(information.transport, ScanMode::Tcp);
        assert_eq!(information.service.as_deref(), Some("smb"));
        assert!(information.product.is_none());
        assert!(information.version.is_none());
        assert_eq!(
            information.observation.as_deref(),
            Some(format!("SMB protocol dialect {dialect:#06x} negotiated successfully").as_str()),
        );
    }
}

#[test]
fn rejects_every_truncated_fixed_response_without_panicking() {
    let reply = negotiate_reply(0x0202);
    for length in 0..128 {
        assert!(
            response_information(&reply[..length], MESSAGE_ID).is_err(),
            "length {length}"
        );
    }
}

#[test]
fn rejects_invalid_headers_and_compounded_or_async_responses() {
    for (offset, value, reason) in [
        (0, 0xff, "protocol ID"),
        (4, 63, "header structure size"),
        (5, 1, "header structure size"),
        (12, 1, "NEGOTIATE"),
        (13, 1, "NEGOTIATE"),
        (16, 0, "response flag"),
        (16, 3, "asynchronous"),
        (20, 128, "compounded"),
        (23, 1, "compounded"),
    ] {
        let mut reply = negotiate_reply(0x0202);
        reply[offset] = value;
        let error = response_information(&reply, MESSAGE_ID).unwrap_err();
        assert!(error.contains(reason), "offset {offset}: {error}");
    }
}

#[test]
fn matches_the_entire_message_id_at_its_wire_offset() {
    let reply = negotiate_reply(0x0202);
    for wrong_id in [0, MESSAGE_ID ^ 1, MESSAGE_ID ^ (1 << 63)] {
        assert!(
            response_information(&reply, wrong_id)
                .unwrap_err()
                .contains("message ID")
        );
    }
    let mut reply = reply;
    reply[32..36].copy_from_slice(&[0xa5; 4]);
    assert!(response_information(&reply, MESSAGE_ID).is_ok());
}

#[test]
fn reports_error_status_before_attempting_to_parse_a_success_body() {
    let mut reply = negotiate_reply(0x0202);
    reply[8..12].copy_from_slice(&0xc000_00bb_u32.to_le_bytes());
    reply.truncate(64);
    let error = response_information(&reply, MESSAGE_ID).unwrap_err();
    assert!(error.contains("status 0xc00000bb"));
}

#[test]
fn rejects_wrong_body_sizes_and_dialects_not_offered_by_the_probe() {
    for size in [0_u16, 36, 64, 66, 0x4100] {
        let mut reply = negotiate_reply(0x0202);
        reply[64..66].copy_from_slice(&size.to_le_bytes());
        assert!(
            response_information(&reply, MESSAGE_ID)
                .unwrap_err()
                .contains("structure size")
        );
    }
    for dialect in [0, 0x02ff, 0x0300, 0x0302, 0x0311, 0xffff] {
        let error = response_information(&negotiate_reply(dialect), MESSAGE_ID).unwrap_err();
        assert!(error.contains("unexpected dialect"));
    }
}

#[test]
fn accepts_a_bounded_security_buffer_with_or_without_padding() {
    for offset in [128_u16, 132] {
        let mut reply = negotiate_reply(0x0210);
        reply[120..122].copy_from_slice(&offset.to_le_bytes());
        reply[122..124].copy_from_slice(&3_u16.to_le_bytes());
        reply.resize(usize::from(offset), 0);
        reply.extend_from_slice(&[0xff, 0x01, 0x80]);
        assert!(response_information(&reply, MESSAGE_ID).is_ok());
    }
}

#[test]
fn rejects_security_buffers_overlapping_fixed_fields_or_exceeding_the_reply() {
    for (offset, length) in [
        (0_u16, 1_u16),
        (64, 1),
        (127, 1),
        (128, 1),
        (129, 1),
        (65535, 65535),
    ] {
        let mut reply = negotiate_reply(0x0202);
        reply[120..122].copy_from_slice(&offset.to_le_bytes());
        reply[122..124].copy_from_slice(&length.to_le_bytes());
        let error = response_information(&reply, MESSAGE_ID).unwrap_err();
        assert!(
            error.contains("security buffer"),
            "offset {offset}, length {length}: {error}"
        );
    }
}

#[test]
fn an_empty_security_buffer_does_not_dereference_its_offset() {
    for offset in [0_u16, 128, u16::MAX] {
        let mut reply = negotiate_reply(0x0202);
        reply[120..122].copy_from_slice(&offset.to_le_bytes());
        assert!(response_information(&reply, MESSAGE_ID).is_ok());
    }
}

#[test]
fn encodes_the_complete_request_before_adding_transport_framing() {
    let guid = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let request = build_smb_negotiate_request(MESSAGE_ID, guid).unwrap();
    let mut expected = [0_u8; 104];
    expected[..16].copy_from_slice(&[0xfe, 0x53, 0x4d, 0x42, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    expected[24..32].copy_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    expected[64..].copy_from_slice(&[
        36, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0x10, 2,
    ]);
    let encoded = encode_smb2_request(&request).unwrap();
    assert_eq!(encoded, expected);
    let framed = frame_smb_message(&encoded).unwrap();
    assert_eq!(&framed[..4], &[0, 0, 0, 104]);
    assert_eq!(&framed[4..], &expected);
}

/// Return at most one byte per poll to exercise read_exact across short reads.
struct ByteReader<'a>(&'a [u8]);

impl AsyncRead for ByteReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let reader = self.get_mut();
        if buffer.remaining() > 0
            && let Some((&byte, remaining)) = reader.0.split_first()
        {
            buffer.put_slice(&[byte]);
            reader.0 = remaining;
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn reader_collects_fragmented_header_and_binary_payload() {
    let mut reader = ByteReader(&[0, 0, 0, 4, 0xfe, 0x53, 0, 0xff]);
    let reply = read_smb_message(&mut reader, Instant::now() + Duration::from_secs(1), 4)
        .await
        .unwrap();
    assert_eq!(reply, [0xfe, 0x53, 0, 0xff]);
    assert!(reader.0.is_empty());
}

#[tokio::test]
async fn reader_returns_one_payload_and_leaves_the_next_record_unread() {
    let mut reader = &[0, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 1, 0xcc][..];
    let reply = read_smb_message(&mut reader, Instant::now() + Duration::from_secs(1), 2)
        .await
        .unwrap();
    assert_eq!(reply, [0xaa, 0xbb]);
    assert_eq!(reader, &[0, 0, 0, 1, 0xcc]);
}

#[tokio::test]
async fn reader_rejects_bad_markers_and_oversized_lengths_before_reading_payload() {
    for (bytes, limit, reason) in [
        (&[1, 0, 0, 1, 0xaa][..], 4, "zero marker"),
        (&[0, 0, 0, 1, 0xaa][..], 0, "limit of 0 bytes"),
        (&[0, 0, 0, 1, 0xaa][..], 0, "payload length 1"),
        (&[0, 255, 255, 255, 0xaa][..], 4096, "limit of 4096 bytes"),
    ] {
        let mut reader = bytes;
        let error = read_smb_message(&mut reader, Instant::now() + Duration::from_secs(1), limit)
            .await
            .unwrap_err();
        assert!(error.contains(reason), "{error}");
        assert_eq!(reader, &[0xaa]);
    }
}

#[tokio::test]
async fn reader_accepts_the_exact_limit_and_an_empty_frame() {
    for (bytes, limit, expected) in [
        (&[0, 0, 0, 2, 1, 2][..], 2, &[1, 2][..]),
        (&[0, 0, 0, 0][..], 0, &[][..]),
    ] {
        let mut reader = bytes;
        assert_eq!(
            read_smb_message(&mut reader, Instant::now() + Duration::from_secs(1), limit)
                .await
                .unwrap(),
            expected,
        );
    }
}

#[tokio::test]
async fn reader_reports_truncated_headers_and_payloads_without_partial_success() {
    let frame = [0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd];
    for length in 0..frame.len() {
        let mut reader = &frame[..length];
        let error = read_smb_message(&mut reader, Instant::now() + Duration::from_secs(1), 4)
            .await
            .unwrap_err();
        let reason = if length < 4 {
            "read error"
        } else {
            "payload read error"
        };
        assert!(error.contains(reason), "length {length}: {error}");
    }
}

#[tokio::test]
async fn reader_rejects_an_expired_deadline_even_when_data_is_immediately_ready() {
    let frame = [0, 0, 0, 1, 0xaa];
    let mut reader = &frame[..];
    let error = read_smb_message(&mut reader, Instant::now(), 1)
        .await
        .unwrap_err();
    assert!(error.contains("deadline has already passed"));
    assert_eq!(reader, &frame);
}

#[tokio::test]
async fn reader_times_out_when_the_header_or_payload_does_not_arrive() {
    for (prefix, reason) in [
        (&[][..], "SMB Direct TCP read timed out"),
        (&[0, 0, 0, 2, 0xaa][..], "payload read timed out"),
    ] {
        let (mut reader, mut peer) = duplex(16);
        peer.write_all(prefix).await.unwrap();
        let error = read_smb_message(&mut reader, Instant::now() + Duration::from_millis(20), 2)
            .await
            .unwrap_err();
        assert!(error.contains(reason), "{error}");
        drop(peer);
    }
}

#[tokio::test]
async fn stream_exchange_writes_the_full_request_then_returns_the_unframed_reply() {
    let request = build_smb_negotiate_request(MESSAGE_ID, [0x55; 16]).unwrap();
    let framed = frame_smb_message(&encode_smb2_request(&request).unwrap()).unwrap();
    let reply = negotiate_reply(0x0210);
    let response_frame = frame_smb_message(&reply).unwrap();
    let (mut client, mut peer) = duplex(8);
    let deadline = Instant::now() + Duration::from_secs(1);
    let (result, ()) = tokio::join!(
        exchange_smb_stream(&mut client, &framed, deadline, 4096),
        async {
            let mut received = vec![0; framed.len()];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, framed);
            peer.write_all(&response_frame).await.unwrap();
        },
    );
    let measured_reply = result.unwrap();
    assert_eq!(measured_reply, reply);
    assert!(response_information(&measured_reply, MESSAGE_ID).is_ok());
}

#[tokio::test]
async fn stream_exchange_reports_write_errors_and_write_timeouts() {
    let (mut client, peer) = duplex(1);
    drop(peer);
    let error = exchange_smb_stream(
        &mut client,
        &[0; 8],
        Instant::now() + Duration::from_secs(1),
        8,
    )
    .await
    .unwrap_err();
    assert!(error.contains("write failed"), "{error}");

    let (mut client, peer) = duplex(1);
    let error = exchange_smb_stream(
        &mut client,
        &[0; 8],
        Instant::now() + Duration::from_millis(20),
        8,
    )
    .await
    .unwrap_err();
    assert!(error.contains("write timed out"), "{error}");
    drop(peer);
}

#[tokio::test]
async fn stream_exchange_rejects_an_expired_deadline_before_writing() {
    let (mut client, mut peer) = duplex(8);
    let error = exchange_smb_stream(&mut client, &[1, 2, 3], Instant::now(), 8)
        .await
        .unwrap_err();
    assert!(error.contains("write deadline has already passed"));
    drop(client);
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty());
}

#[tokio::test]
async fn expired_probe_returns_before_creating_a_network_connection() {
    // The expiration guard returns before TcpStream::connect is constructed or polled.
    let error = probe(
        "192.0.2.1:445".parse().unwrap(),
        0,
        [0; 16],
        Instant::now(),
        4096,
    )
    .await
    .unwrap_err();
    assert!(error.contains("connection deadline has already passed"));
}
