//! SYN-specific fields and SYN/reset header construction using shared raw-TCP helpers.

use super::constants::{DATA_OFFSET_NO_OPTIONS, FLAG_RST, FLAG_SYN, TCP_HEADER_BYTES};
use crate::model::syn::{SynProbe, TcpReply};
use std::net::Ipv4Addr;

pub(super) use crate::scan::raw_tcp::checksum::apply_tcp_checksum;
#[cfg(test)]
pub(super) use crate::scan::raw_tcp::checksum::{internet_checksum, ipv4_pseudo_header};
#[cfg(test)]
pub(super) use crate::scan::raw_tcp::packet::port_to_bytes;
pub(super) use crate::scan::raw_tcp::packet::{
    empty_tcp_header, parse_ipv4_packet, parse_tcp_reply, write_ports,
};

/// Fill sequence, acknowledgment, length, flags, window, and urgent fields.
/// Sequence: bytes 4..8; acknowledgment: 8..12 (zero); byte 12: 0x50;
/// byte 13: 0x02 (SYN); window: 14..16; urgent pointer: 18..20 (zero).
/// Preserve ports and checksum bytes. Encode multi-byte numbers as big-endian.
pub(super) fn write_syn_fields(
    _header: &mut [u8; TCP_HEADER_BYTES],
    _sequence_number: u32,
    _window: u16,
) -> Result<(), String> {
    _header[4..8].copy_from_slice(&_sequence_number.to_be_bytes());
    _header[8..12].copy_from_slice(&0u32.to_be_bytes()); // Acknowledgment number
    _header[12] = DATA_OFFSET_NO_OPTIONS; // Data offset and reserved bits
    _header[13] = FLAG_SYN; // Flags (SYN)
    _header[14..16].copy_from_slice(&_window.to_be_bytes());
    _header[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

    Ok(())
}

/// Combine header fields and checksum to return a complete TCP SYN header.
/// Addresses are needed for the checksum; they are not stored in the TCP header.
/// This function builds bytes only and sends nothing.
pub(super) fn build_syn_header(
    _source: Ipv4Addr,
    _destination: Ipv4Addr,
    _source_port: u16,
    _destination_port: u16,
    _sequence_number: u32,
    _window: u16,
) -> Result<[u8; TCP_HEADER_BYTES], String> {
    let mut header = [0; TCP_HEADER_BYTES];
    write_ports(&mut header, _source_port, _destination_port)?;
    write_syn_fields(&mut header, _sequence_number, _window)?;
    apply_tcp_checksum(&mut header, _source, _destination)?;

    Ok(header)
}

/// Build an appropriate reset for a validated matching SYN/ACK, including its checksum.
/// Do not reuse the SYN builder unchanged: reset flags and sequence handling differ.
pub(super) fn build_rst_header(
    _probe: &SynProbe,
    _reply: &TcpReply,
) -> Result<[u8; TCP_HEADER_BYTES], String> {
    let mut _empty_header = empty_tcp_header()?;
    write_ports(
        &mut _empty_header,
        _probe.source.port(),
        _probe.destination.port(),
    )?;

    let ack_big_endian = _reply.acknowledgment_number.to_be_bytes();
    _empty_header[4..8].copy_from_slice(&ack_big_endian);
    _empty_header[12] = DATA_OFFSET_NO_OPTIONS;
    _empty_header[13] = FLAG_RST;
    apply_tcp_checksum(
        &mut _empty_header,
        *_probe.source.ip(),
        *_probe.destination.ip(),
    )?;

    Ok(_empty_header)
}
