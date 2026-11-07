use super::{build_nfs_null_call, is_nfs_candidate, probe, response_information};
use crate::model::ScanMode;
use tokio::time::Instant;

// Independent NFSv3 NULL request: RPC v2, program 100003, version 3, procedure 0.
const NFS_NULL_CALL: [u8; 40] = [
    0x12, 0x34, 0x56, 0x78, // XID.
    0, 0, 0, 0, // CALL.
    0, 0, 0, 2, // RPC protocol version.
    0, 1, 0x86, 0xa3, // Program 100003.
    0, 0, 0, 3, // NFS program version.
    0, 0, 0, 0, // NULL.
    0, 0, 0, 0, // AUTH_NONE credential.
    0, 0, 0, 0, // Empty credential body.
    0, 0, 0, 0, // AUTH_NONE verifier.
    0, 0, 0, 0, // Empty verifier body.
];

const NULL_REPLY: [u8; 24] = [
    0x12, 0x34, 0x56, 0x78, // XID.
    0, 0, 0, 1, // REPLY.
    0, 0, 0, 0, // MSG_ACCEPTED.
    0, 0, 0, 0, // AUTH_NONE verifier.
    0, 0, 0, 0, // Empty verifier body.
    0, 0, 0, 0, // SUCCESS, without procedure results.
];

#[test]
fn selects_only_the_initial_nfs_tcp_candidate() {
    for (port, expected) in [
        (2049, true),
        (0, false),
        (111, false),
        (2048, false),
        (2050, false),
        (65535, false),
    ] {
        assert_eq!(is_nfs_candidate(port), expected);
    }
}

#[test]
fn builds_the_unframed_nfs_request_and_preserves_transaction_ids() {
    assert_eq!(build_nfs_null_call(0x12345678).unwrap(), NFS_NULL_CALL);
    for xid in [0_u32, 1, 0x80000000, u32::MAX] {
        let call = build_nfs_null_call(xid).unwrap();
        assert_eq!(call.len(), 40);
        assert_eq!(&call[..4], &xid.to_be_bytes());
        assert_eq!(&call[4..], &NFS_NULL_CALL[4..]);
    }
}

#[test]
fn identifies_null_replies_with_empty_and_padded_verifiers() {
    let mut padded = NULL_REPLY[..12].to_vec();
    padded.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0xaa, 0, 0, 0]);
    padded.extend_from_slice(&[0; 4]); // SUCCESS.
    for reply in [&NULL_REPLY[..], &padded[..]] {
        let information = response_information(reply, 0x12345678).unwrap();
        assert_eq!(information.transport, ScanMode::Tcp);
        assert_eq!(information.service.as_deref(), Some("nfs"));
        assert!(information.product.is_none());
        assert!(information.version.is_none());
        let observation = information.observation.as_deref().unwrap();
        assert!(observation.contains("RPC program 100003"));
        assert!(observation.contains("NFS protocol version 3"));
        assert!(observation.contains("NULL procedure succeeded"));
    }
}

#[test]
fn rejects_incomplete_unmatched_denied_and_unsuccessful_replies() {
    for length in 0..NULL_REPLY.len() {
        assert!(response_information(&NULL_REPLY[..length], 0x12345678).is_err());
    }
    assert!(response_information(&NULL_REPLY, 0x12345679).is_err());
    for (index, value) in [(7, 0), (11, 1), (23, 1), (23, 2)] {
        let mut reply = NULL_REPLY;
        reply[index] = value;
        assert!(response_information(&reply, 0x12345678).is_err());
    }
}

#[test]
fn rejects_payload_after_an_otherwise_successful_null_reply() {
    for extra in [&[0_u8][..], &[0, 0, 0, 0][..], &[0xff, 0xaa][..]] {
        let mut reply = NULL_REPLY.to_vec();
        reply.extend_from_slice(extra);
        let error = response_information(&reply, 0x12345678).unwrap_err();
        assert!(error.contains("unexpected payload"));
    }
}

#[tokio::test]
async fn expired_probe_deadline_returns_before_connecting() {
    let error = probe("192.0.2.1:2049".parse().unwrap(), 1, Instant::now(), 4096)
        .await
        .unwrap_err();
    assert!(error.contains("RPC connection timed out"));
}
