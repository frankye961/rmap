use super::{
    append_u32, build_portmapper_null_call, decode_record_marker, frame_rpc_record,
    is_rpc_candidate, read_u32, record_marker, response_information, skip_rpc_verifier,
    validate_portmapper_null_reply, validate_rpc_reply_header,
};

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
        assert!(error.contains("RPC NULL procedure did not succeed"));
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
