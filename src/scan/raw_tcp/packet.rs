//! Existing TCP field encoding and validated IPv4/TCP parsing shared across scan methods.

use super::checksum::{internet_checksum, ipv4_pseudo_header};
use super::constants::{
    IP_PROTOCOL_TCP, IPV4_FRAGMENT_OFFSET, IPV4_MORE_FRAGMENTS, MIN_IPV4_HEADER_BYTES,
    TCP_HEADER_BYTES,
};
use crate::model::syn::{ParsedIpv4Packet, TcpReply};
use std::net::Ipv4Addr;

/// Encode a TCP port in network byte order.
pub(in crate::scan) fn port_to_bytes(_port: u16) -> Result<[u8; 2], String> {
    Ok(_port.to_be_bytes())
}

/// Create a zero-filled, 20-byte TCP header buffer.
pub(in crate::scan) fn empty_tcp_header() -> Result<[u8; TCP_HEADER_BYTES], String> {
    Ok([0; TCP_HEADER_BYTES])
}

/// Write the source port at bytes 0..2 and destination at bytes 2..4.
/// Leave all other fields unchanged.
pub(in crate::scan) fn write_ports(
    _header: &mut [u8; TCP_HEADER_BYTES],
    _source_port: u16,
    _destination_port: u16,
) -> Result<(), String> {
    let source_bytes = port_to_bytes(_source_port)?;
    let destination_bytes = port_to_bytes(_destination_port)?;

    _header[0..2].copy_from_slice(&source_bytes);
    _header[2..4].copy_from_slice(&destination_bytes);

    Ok(())
}

/// Validate IPv4 version, IHL, total length, header checksum, protocol, and
/// fragmentation before borrowing the TCP segment. Do not assume a 20-byte IP header.
pub(in crate::scan) fn parse_ipv4_packet(_bytes: &[u8]) -> Result<ParsedIpv4Packet<'_>, String> {
    if _bytes.len() < MIN_IPV4_HEADER_BYTES {
        return Err("Byte length is too small".into());
    }

    let _version = _bytes[0] >> 4;
    let _header_len = usize::from(_bytes[0] & 0x0F) * 4;

    if _version != 4 {
        return Err("Packet is not IPv4".into());
    }

    if _header_len < MIN_IPV4_HEADER_BYTES || _header_len > _bytes.len() {
        return Err("Header length is too big".into());
    }

    let _total_len = usize::from(u16::from_be_bytes([_bytes[2], _bytes[3]]));

    if _total_len < _header_len || _total_len > _bytes.len() {
        return Err("Invalid IPv4 total length".into());
    }

    if _bytes[9] != IP_PROTOCOL_TCP {
        return Err("IPv4 packet does not contain TCP".into());
    }

    if internet_checksum(&_bytes[.._header_len])? != 0 {
        return Err("Invalid IPv4 header checksum".into());
    }

    let _fragment = u16::from_be_bytes([_bytes[6], _bytes[7]]);

    if _fragment & IPV4_MORE_FRAGMENTS != 0 || _fragment & IPV4_FRAGMENT_OFFSET != 0 {
        return Err("Fragmented IPv4 packets are not supported".into());
    }

    let _source = Ipv4Addr::new(_bytes[12], _bytes[13], _bytes[14], _bytes[15]);
    let _destination = Ipv4Addr::new(_bytes[16], _bytes[17], _bytes[18], _bytes[19]);

    Ok(ParsedIpv4Packet {
        source: _source,
        destination: _destination,
        tcp_segment: &_bytes[_header_len.._total_len],
    })
}

/// Validate TCP length, data offset, and pseudo-header checksum, then extract fields.
/// Length and checksum calculations must include any payload and TCP options.
pub(in crate::scan) fn parse_tcp_reply(_packet: &ParsedIpv4Packet<'_>) -> Result<TcpReply, String> {
    if _packet.tcp_segment.len() < TCP_HEADER_BYTES {
        return Err("TCP segment too small".into());
    }

    let _header_len = usize::from(_packet.tcp_segment[12] >> 4) * 4;

    if _header_len < TCP_HEADER_BYTES || _header_len > _packet.tcp_segment.len() {
        return Err("Invalid Header length".into());
    }

    let _segment_length = u16::try_from(_packet.tcp_segment.len())
        .map_err(|_| "TCP segment is too large".to_string())?;

    let _pseudo_header = ipv4_pseudo_header(_packet.source, _packet.destination, _segment_length)?;

    let mut _checksum_vec = Vec::with_capacity(_pseudo_header.len() + _packet.tcp_segment.len());

    _checksum_vec.extend_from_slice(&_pseudo_header);
    _checksum_vec.extend_from_slice(_packet.tcp_segment);

    if internet_checksum(&_checksum_vec)? != 0 {
        return Err("Invalid TCP checksum".into());
    }

    let _source_port = u16::from_be_bytes([_packet.tcp_segment[0], _packet.tcp_segment[1]]);

    let _dest_port = u16::from_be_bytes([_packet.tcp_segment[2], _packet.tcp_segment[3]]);

    let _seq_number = u32::from_be_bytes([
        _packet.tcp_segment[4],
        _packet.tcp_segment[5],
        _packet.tcp_segment[6],
        _packet.tcp_segment[7],
    ]);

    let _ack = u32::from_be_bytes([
        _packet.tcp_segment[8],
        _packet.tcp_segment[9],
        _packet.tcp_segment[10],
        _packet.tcp_segment[11],
    ]);

    let _flags = _packet.tcp_segment[13];

    Ok(TcpReply {
        source_port: _source_port,
        destination_port: _dest_port,
        sequence_number: _seq_number,
        acknowledgment_number: _ack,
        flags: _flags,
    })
}
