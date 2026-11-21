//! Independent wire fixture for FIN-only encoding; no socket operations.

use std::net::SocketAddrV4;

use super::build_fin_header;
use crate::scan::fin::FinProbe;

#[test]
fn encodes_fin_only_with_zero_acknowledgment_and_the_expected_checksum() {
    let probe = FinProbe {
        source: SocketAddrV4::new([192, 0, 2, 10].into(), 40000),
        destination: SocketAddrV4::new([198, 51, 100, 20].into(), 443),
        sequence_number: 0x1020_3040,
    };
    // Independent IPv4 pseudo-header + TCP one's-complement checksum: 0xe135.
    let expected = [
        0x9c, 0x40, 0x01, 0xbb, 0x10, 0x20, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x04,
        0x00, 0xe1, 0x35, 0x00, 0x00,
    ];

    assert_eq!(build_fin_header(&probe, 1024).unwrap(), expected);
}
