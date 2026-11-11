//! ACK-specific header fields; reuse existing port and checksum helpers when implementing.

use super::constants::TCP_HEADER_BYTES;
use super::probe::AckProbe;
use crate::scan::raw_tcp::checksum::apply_tcp_checksum;
use crate::scan::raw_tcp::packet::{empty_tcp_header, write_ports};

/// Build a fixed TCP ACK header from the retained probe fields and advertised window.
/// Reuse port encoding and the TCP pseudo-header checksum; no packet is sent here.
pub(super) fn build_ack_header(
    _probe: &AckProbe,
    _window: u16,
) -> Result<[u8; TCP_HEADER_BYTES], String> {
    let mut _empty_header = empty_tcp_header()?;
    write_ports(
        &mut _empty_header,
        _probe.source.port(),
        _probe.destination.port(),
    )?;

    let ack_big_endian = _probe.sequence_number.to_be_bytes();
    _empty_header[4..8].copy_from_slice(&ack_big_endian);
    _empty_header[8..12].copy_from_slice(&_probe.acknowledgment_number.to_be_bytes());
    _empty_header[12] = super::constants::DATA_OFFSET_NO_OPTIONS;
    _empty_header[13] = super::constants::FLAG_ACK;
    _empty_header[14..16].copy_from_slice(&_window.to_be_bytes());
    apply_tcp_checksum(
        &mut _empty_header,
        *_probe.source.ip(),
        *_probe.destination.ip(),
    )?;
    Ok(_empty_header)
}

/// Write sequence, acknowledgment, data offset, ACK flag, window and urgent pointer.
/// Keep the caller's source/destination ports and checksum field intact.
pub(super) fn write_ack_fields(
    _header: &mut [u8; TCP_HEADER_BYTES],
    _sequence_number: u32,
    _acknowledgment_number: u32,
    _window: u16,
) -> Result<(), String> {
    Err("ACK field encoding is not implemented".into())
}
