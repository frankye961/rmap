use crate::scan::fin::FinProbe;
use crate::scan::raw_tcp::checksum::apply_tcp_checksum;
use crate::scan::raw_tcp::constants::{DATA_OFFSET_NO_OPTIONS, FLAG_FIN, TCP_HEADER_BYTES};
use crate::scan::raw_tcp::packet::{empty_tcp_header, write_ports};

pub(super) fn build_fin_header(
    _fin_probe: &FinProbe,
    window: u16,
) -> Result<[u8; TCP_HEADER_BYTES], String> {
    let mut _header = empty_tcp_header()?;
    write_ports(
        &mut _header,
        _fin_probe.source.port(),
        _fin_probe.destination.port(),
    )?;
    write_fin_fields(&mut _header, _fin_probe.sequence_number, window)?;
    apply_tcp_checksum(
        &mut _header,
        *_fin_probe.source.ip(),
        *_fin_probe.destination.ip(),
    )?;
    Ok(_header)
}

pub(super) fn write_fin_fields(
    _header: &mut [u8; TCP_HEADER_BYTES],
    _sequence_number: u32,
    _window: u16,
) -> Result<(), String> {
    _header[4..8].copy_from_slice(&_sequence_number.to_be_bytes());
    _header[12] = DATA_OFFSET_NO_OPTIONS;
    _header[13] = FLAG_FIN;
    _header[14..16].copy_from_slice(&_window.to_be_bytes());
    _header[18..20].copy_from_slice(&0u16.to_be_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/scan/fin_packet.rs"]
mod tests;
