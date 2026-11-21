use crate::scan::fin::{FinProbe, PreparedProbe};
use crate::scan::raw_tcp::socket::{
    create_unconnected_tcp_socket, discover_source_ip, prepare_raw_tcp_socket, raw_socket_error,
    register_raw_socket,
};
use std::net::{SocketAddr, SocketAddrV4};

/// Select the source address, reserve a TCP source port, build the FIN header,
/// and register a nonblocking raw socket. Sending belongs to the scan entry point.
pub(super) fn prepare_probe(_target: SocketAddr) -> Result<PreparedProbe, String> {
    let _destination = match _target {
        SocketAddr::V4(_address) => _address,
        SocketAddr::V6(_) => {
            return Err("FIN probing supports IPv4 only; IPv6 is not supported".into());
        }
    };

    let _local_ip = discover_source_ip(_destination).map_err(|e| e.to_string())?;
    let (_source_socket, _source_port) =
        create_unconnected_tcp_socket(_local_ip).map_err(|e| e.to_string())?;
    let _seq_num = generate_probe_numbers()?;
    let _source_address = SocketAddrV4::new(_local_ip, _source_port);
    let _probe = map_fin_probe(_source_address, _destination, _seq_num);
    let _header = crate::scan::fin::packet::build_fin_header(
        &_probe,
        crate::scan::fin::constants::FIN_WINDOW,
    )?;
    let _raw_socket = prepare_raw_tcp_socket(_local_ip).map_err(raw_socket_error)?;
    let _registered_socket = register_raw_socket(_raw_socket)?;
    Ok(PreparedProbe {
        _source_socket,
        probe: _probe,
        header: _header,
        socket: _registered_socket,
    })
}

pub(super) fn generate_probe_numbers() -> Result<u32, String> {
    let _seq_num: u32 = getrandom::u32().map_err(|e| e.to_string())?;
    Ok(_seq_num)
}

fn map_fin_probe(_src: SocketAddrV4, _destination: SocketAddrV4, _seq_num: u32) -> FinProbe {
    FinProbe {
        source: _src,
        destination: _destination,
        sequence_number: _seq_num,
    }
}

#[cfg(test)]
#[path = "../../../tests/scan/fin_probe.rs"]
mod tests;
