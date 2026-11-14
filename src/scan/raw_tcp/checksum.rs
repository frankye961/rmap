//! Existing Internet-checksum and IPv4 pseudo-header helpers shared by raw TCP modes.

use super::constants::{IP_PROTOCOL_TCP, PSEUDO_HEADER_BYTES, TCP_HEADER_BYTES};
use std::net::Ipv4Addr;

/// Compute the Internet checksum over arbitrary bytes.
/// Sum big-endian 16-bit words, fold carries, and complement the final sum.
/// For an odd byte count, pad with a zero byte for calculation only.
pub(in crate::scan) fn internet_checksum(_data: &[u8]) -> Result<u16, String> {
    let mut sum: u32 = 0;
    let (chunks, remainder) = _data.as_chunks::<2>();

    for chunk in chunks {
        // Convert the 2 big-endian bytes into a host u16, then cast to u32
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;

        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    if let Some(&last_byte) = remainder.first() {
        let word = u16::from_be_bytes([last_byte, 0]) as u32;
        sum = sum.wrapping_add(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    Ok(!(sum as u16))
}

/// Build the 12-byte IPv4 pseudo-header used by the TCP checksum.
/// Layout: source address (4), destination address (4), zero (1), protocol 6 (1),
/// TCP segment length (2, big-endian). Length includes TCP header and payload only.
/// The pseudo-header is checksum input, not part of the transmitted TCP segment.
pub(in crate::scan) fn ipv4_pseudo_header(
    _source: Ipv4Addr,
    _destination: Ipv4Addr,
    _tcp_length: u16,
) -> Result<[u8; PSEUDO_HEADER_BYTES], String> {
    let mut header = [0; PSEUDO_HEADER_BYTES];
    header[0..4].copy_from_slice(&_source.octets());
    header[4..8].copy_from_slice(&_destination.octets());
    header[8] = 0;
    header[9] = IP_PROTOCOL_TCP;
    header[10..12].copy_from_slice(&_tcp_length.to_be_bytes());
    Ok(header)
}

/// Zero bytes 16..18, checksum pseudo-header plus TCP header, then
/// insert the big-endian checksum at bytes 16..18.
/// For this fixed header, TCP length is 20 and combined checksum input is 32 bytes.
pub(in crate::scan) fn apply_tcp_checksum(
    _header: &mut [u8; TCP_HEADER_BYTES],
    _source: Ipv4Addr,
    _destination: Ipv4Addr,
) -> Result<(), String> {
    _header[16..18].copy_from_slice(&0u16.to_be_bytes()); // Zero the checksum field

    let pseudo_header = ipv4_pseudo_header(_source, _destination, TCP_HEADER_BYTES as u16)?;
    let mut checksum_input = Vec::with_capacity(PSEUDO_HEADER_BYTES + TCP_HEADER_BYTES);
    checksum_input.extend_from_slice(&pseudo_header);
    checksum_input.extend_from_slice(_header);

    let checksum = internet_checksum(&checksum_input)?;
    _header[16..18].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}
