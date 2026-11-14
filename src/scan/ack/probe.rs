//! ACK probe preparation and random sequence/acknowledgment values.

use std::net::{SocketAddr, SocketAddrV4};

use super::constants::ACK_WINDOW;
use super::packet::build_ack_header;
use super::{AckProbe, PreparedProbe};
use crate::scan::raw_tcp::socket::{
    create_unconnected_tcp_socket, discover_source_ip, prepare_raw_tcp_socket, raw_socket_error,
    register_raw_socket,
};

/// Select the source address, reserve a TCP source port, build the ACK header,
/// and register a nonblocking raw socket. Sending belongs to the scan entry point.
pub(super) fn prepare_probe(_target: SocketAddr) -> Result<PreparedProbe, String> {
    let _destination = match _target {
        SocketAddr::V4(_address) => _address,
        SocketAddr::V6(_) => {
            return Err("ACK probing supports IPv4 only; IPv6 is not supported".into());
        }
    };

    let _local_ip = discover_source_ip(_destination).map_err(|e| e.to_string())?;
    let (_source_socket, _source_port) =
        create_unconnected_tcp_socket(_local_ip).map_err(|e| e.to_string())?;
    let (_seq_num, _ack_num) = generate_probe_numbers()?;
    let _source_address = SocketAddrV4::new(_local_ip, _source_port);
    let _probe = map_ack_probe(_source_address, _destination, _seq_num, _ack_num);
    let _header = build_ack_header(&_probe, ACK_WINDOW)?;
    let _raw_socket = prepare_raw_tcp_socket(_local_ip).map_err(raw_socket_error)?;
    let _registered_socket = register_raw_socket(_raw_socket)?;
    Ok(PreparedProbe {
        source_socket: _source_socket,
        probe: _probe,
        header: _header,
        socket: _registered_socket,
    })
}

/// Obtain the sequence and acknowledgment values that will be retained in AckProbe.
pub(super) fn generate_probe_numbers() -> Result<(u32, u32), String> {
    let _seq_num: u32 = getrandom::u32().map_err(|e| e.to_string())?;
    let _ack_num: u32 = getrandom::u32().map_err(|e| e.to_string())?;
    Ok((_seq_num, _ack_num))
}

fn map_ack_probe(
    _src: SocketAddrV4,
    _destination: SocketAddrV4,
    _seq_num: u32,
    _ack_num: u32,
) -> AckProbe {
    AckProbe {
        source: _src,
        destination: _destination,
        sequence_number: _seq_num,
        acknowledgment_number: _ack_num,
    }
}
