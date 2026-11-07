//! Identify NFSv3 over TCP using a bounded RPC NULL exchange.

use std::net::SocketAddr;

use tokio::time::Instant;

use crate::model::service_information::ServiceInformation;

const NFS_PORT: u16 = 2049;
const NFS_PROGRAM: u32 = 100003;
const NFS_VERSION: u32 = 3;
const NULL_PROCEDURE: u32 = 0;

/// Select the initial TCP candidate port; a validated reply establishes identity.
pub(super) fn is_nfs_candidate(_port: u16) -> bool {
    _port == NFS_PORT
}

/// Build an argument-free NFSv3 NULL call without a TCP record marker.
pub(super) fn build_nfs_null_call(_xid: u32) -> Vec<u8> {
    super::rpc::build_rpc_call(_xid, NFS_PROGRAM, NFS_VERSION, NULL_PROCEDURE)
}

/// Exchange one NFSv3 NULL call under the caller's deadline and reply-size limit.
pub(super) async fn probe(
    _target: SocketAddr,
    _xid: u32,
    _deadline: Instant,
    _max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let _unframed_request = build_nfs_null_call(_xid);
    super::rpc::exchange_rpc_call(_target, &_unframed_request, _deadline, _max_bytes).await
}

/// Validate an NFSv3 NULL reply and prepare structured service information.
pub(super) fn response_information(
    _reply: &[u8],
    _expected_xid: u32,
) -> Result<ServiceInformation, String> {
    let _cursor = super::rpc::validate_rpc_success_reply(_reply, _expected_xid)?;
    if _cursor != _reply.len() {
        return Err("NFSv3 NULL reply has unexpected payload".into());
    }
    Ok(crate::mapper::service_information::map_tcp_service(
        "nfs",
        None,
        None,
        Some(&format!(
            "RPC program {NFS_PROGRAM}; NFS protocol version {NFS_VERSION}; NULL procedure succeeded"
        )),
    ))
}

#[cfg(test)]
#[path = "../../tests/scan/nfs.rs"]
mod tests;
