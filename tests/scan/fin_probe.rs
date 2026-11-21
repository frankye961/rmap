//! Input validation before FIN socket setup; no live probes or raw privileges.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use super::prepare_probe;

#[test]
fn rejects_ipv6_before_attempting_socket_preparation() {
    let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1883, 0, 0));
    let error = prepare_probe(target)
        .err()
        .expect("IPv6 targets must be rejected before creating sockets");

    assert_eq!(
        error,
        "FIN probing supports IPv4 only; IPv6 is not supported"
    );
}
