use std::net::Ipv4Addr;

use super::{
    apply_tcp_checksum, build_syn_header, empty_tcp_header, internet_checksum, ipv4_pseudo_header,
    port_to_bytes, write_ports, write_syn_fields,
};

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const PSEUDO_HEADER: [u8; 12] = [192, 0, 2, 10, 198, 51, 100, 20, 0, 6, 0, 20];
// Fixed wire-format fixture: ports 40000 -> 80, sequence 1, SYN, window 1024.
// Its checksum is 0x22ff for the source and destination above.
const SYN_HEADER: [u8; 20] = [
    0x9c, 0x40, 0, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 4, 0, 0x22, 0xff, 0, 0,
];

fn checksum_input(header: &[u8; 20]) -> Vec<u8> {
    let mut input = PSEUDO_HEADER.to_vec();
    input.extend_from_slice(header);
    input
}

#[test]
fn ports_are_encoded_in_network_byte_order() {
    for (port, expected) in [
        (0, [0, 0]),
        (80, [0, 0x50]),
        (40000, [0x9c, 0x40]),
        (65535, [0xff, 0xff]),
    ] {
        assert_eq!(port_to_bytes(port).unwrap(), expected);
    }
}

#[test]
fn empty_header_contains_twenty_zero_bytes() {
    assert_eq!(empty_tcp_header().unwrap(), [0; 20]);
}

#[test]
fn writing_ports_preserves_other_header_fields() {
    let mut header = [0xab; 20];
    write_ports(&mut header, 40000, 80).unwrap();
    assert_eq!(&header[..4], &[0x9c, 0x40, 0, 0x50]);
    assert_eq!(&header[4..], &[0xab; 16]);
}

#[test]
fn syn_fields_use_correct_offsets_and_preserve_ports_and_checksum() {
    let mut header = [0xab; 20];
    write_syn_fields(&mut header, 0x01020304, 1024).unwrap();
    assert_eq!(
        header,
        [
            0xab, 0xab, 0xab, 0xab, 1, 2, 3, 4, 0, 0, 0, 0, 0x50, 2, 4, 0, 0xab, 0xab, 0, 0,
        ]
    );
}

#[test]
fn checksum_matches_fixed_even_odd_and_carry_fixtures() {
    for (input, expected) in [
        (&[][..], 0xffff),
        (&[0, 1, 0, 2][..], 0xfffc),
        (&[0xff, 0xff, 0, 1][..], 0xfffe),
        (&[1][..], 0xfeff),
        (&[1, 2, 3][..], 0xfbfd),
        (&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7][..], 0x220d),
    ] {
        assert_eq!(
            internet_checksum(input).unwrap(),
            expected,
            "input: {input:02x?}"
        );
    }
}

#[test]
fn checksum_preserves_carries_beyond_the_u32_accumulator() {
    // All 0xffff words must checksum to zero, regardless of their count.
    // This exceeds one TCP segment, but exercises the helper's arbitrary-slice contract.
    assert_eq!(internet_checksum(&vec![0xff; 131_076]).unwrap(), 0);
}

#[test]
fn pseudo_header_matches_ipv4_addresses_protocol_and_tcp_length() {
    assert_eq!(
        ipv4_pseudo_header(SOURCE, DESTINATION, 20).unwrap(),
        PSEUDO_HEADER
    );
    let maximum = ipv4_pseudo_header(SOURCE, DESTINATION, u16::MAX).unwrap();
    assert_eq!(&maximum[..10], &PSEUDO_HEADER[..10]);
    assert_eq!(&maximum[10..], &[0xff, 0xff]);
}

#[test]
fn checksum_insertion_replaces_old_checksum_and_matches_wire_fixture() {
    let mut header = SYN_HEADER;
    header[16..18].copy_from_slice(&[0xab, 0xcd]);
    apply_tcp_checksum(&mut header, SOURCE, DESTINATION).unwrap();
    assert_eq!(header, SYN_HEADER);
    apply_tcp_checksum(&mut header, SOURCE, DESTINATION).unwrap();
    assert_eq!(header, SYN_HEADER);
    assert_eq!(internet_checksum(&checksum_input(&header)).unwrap(), 0);
}

#[test]
fn verification_detects_changed_port_or_destination_address() {
    let input = checksum_input(&SYN_HEADER);
    assert_eq!(internet_checksum(&input).unwrap(), 0);
    let mut changed_port = input.clone();
    changed_port[15] ^= 1;
    assert_ne!(internet_checksum(&changed_port).unwrap(), 0);
    let mut changed_destination = input;
    changed_destination[7] ^= 1;
    assert_ne!(internet_checksum(&changed_destination).unwrap(), 0);
}

#[test]
fn builder_returns_complete_syn_header_including_checksum() {
    let header = build_syn_header(SOURCE, DESTINATION, 40000, 80, 1, 1024).unwrap();
    assert_eq!(header, SYN_HEADER);
    assert_eq!(internet_checksum(&checksum_input(&header)).unwrap(), 0);
}
