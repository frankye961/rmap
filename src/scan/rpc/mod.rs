//! Portmapper identification and enumeration over bounded ONC RPC exchanges.

use crate::mapper::service_information::map_portmapper_service;
use crate::model::service_information::ServiceInformation;
use std::net::SocketAddr;
use tokio::time::Instant;

mod constants;
mod record;
mod reply;
mod request;
mod transport;

pub(super) use constants::{MAX_DUMP_ENTRIES, MAX_REPLY_BYTES};
use reply::validate_portmapper_null_reply;
pub(super) use reply::{parse_portmapper_dump_reply, validate_rpc_success_reply};
pub(super) use request::build_rpc_call;
use request::{build_portmapper_dump_call, build_portmapper_null_call};
pub(super) use transport::exchange_rpc_call;

/// Select an initial TCP probe candidate; the port alone does not identify RPC.
pub(super) fn is_rpc_candidate(_port: u16) -> bool {
    _port == constants::PORTMAPPER_PORT
}

/// Exchange one portmapper NULL call over TCP under the caller's shared deadline.
/// Return the assembled reply body; the result handler validates it against _xid.
pub(super) async fn probe(
    _target: SocketAddr,
    _xid: u32,
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let _null_call = build_portmapper_null_call(_xid);
    exchange_rpc_call(_target, &_null_call, _deadline, _max_bytes).await
}

/// Exchange a DUMP request; the caller validates and parses its list payload.
pub(super) async fn probe_dump(
    _target: SocketAddr,
    _xid: u32,
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let _dump_call = build_portmapper_dump_call(_xid);
    exchange_rpc_call(_target, &_dump_call, _deadline, _max_bytes).await
}

/// Validate a complete, reassembled reply body before mapping service information.
/// The caller must remove TCP record markers and retain the request's XID.
pub(super) fn response_information(
    _reply: &[u8],
    _expected_xid: u32,
) -> Result<ServiceInformation, String> {
    validate_portmapper_null_reply(_reply, _expected_xid)?;
    Ok(map_portmapper_service(
        constants::PORTMAPPER_PROGRAM,
        constants::PORTMAPPER_VERSION,
    ))
}

#[cfg(test)]
#[path = "../../../tests/scan/rpc.rs"]
mod tests;
