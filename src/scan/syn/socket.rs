//! Compatibility imports for the existing SYN scanner's shared raw-TCP socket helpers.

pub(super) use crate::scan::raw_tcp::socket::{
    check_deadline, create_unconnected_tcp_socket, discover_source_ip, prepare_raw_tcp_socket,
    raw_socket_error, receive_raw_packet, register_raw_socket, send_tcp_header, timeout_error,
};
