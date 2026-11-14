use super::AckProbe;
use super::constants::{DATA_OFFSET_NO_OPTIONS, FLAG_ACK, TCP_HEADER_BYTES};
use crate::scan::raw_tcp::checksum::apply_tcp_checksum;
use crate::scan::raw_tcp::packet::{empty_tcp_header, write_ports};

pub(super) fn build_ack_header(
    _probe: &AckProbe,
    _window: u16,
) -> Result<[u8; TCP_HEADER_BYTES], String> {
    let mut _header = empty_tcp_header()?;
    write_ports(
        &mut _header,
        _probe.source.port(),
        _probe.destination.port(),
    )?;

    write_ack_fields(
        &mut _header,
        _probe.sequence_number,
        _probe.acknowledgment_number,
        _window,
    )?;
    apply_tcp_checksum(&mut _header, *_probe.source.ip(), *_probe.destination.ip())?;
    Ok(_header)
}

pub(super) fn write_ack_fields(
    _header: &mut [u8; TCP_HEADER_BYTES],
    _sequence_number: u32,
    _acknowledgment_number: u32,
    _window: u16,
) -> Result<(), String> {
    _header[4..8].copy_from_slice(&_sequence_number.to_be_bytes());
    _header[8..12].copy_from_slice(&_acknowledgment_number.to_be_bytes());
    _header[12] = DATA_OFFSET_NO_OPTIONS;
    _header[13] = FLAG_ACK;
    _header[14..16].copy_from_slice(&_window.to_be_bytes());
    _header[18..20].copy_from_slice(&0u16.to_be_bytes());

    Ok(())
}
