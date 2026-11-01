use super::{append_u32, build_portmapper_null_call, frame_rpc_record, read_u32, record_marker};

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
