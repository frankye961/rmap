use std::io::{self, ErrorKind};
use std::time::Duration;

use super::classify_response;
use crate::model::{PortStatus, ScanMode};
use crate::scan::scan;

#[test]
fn silence_is_open_or_filtered_and_refusal_is_closed() {
    for (kind, expected) in [
        (ErrorKind::TimedOut, PortStatus::OpenOrFiltered),
        (ErrorKind::WouldBlock, PortStatus::OpenOrFiltered),
        (ErrorKind::ConnectionRefused, PortStatus::Closed),
        (ErrorKind::PermissionDenied, PortStatus::Unknown),
    ] {
        let (status, _) = classify_response(Err(io::Error::from(kind)), &[0; 1024]);
        assert_eq!(status, expected);
    }
}

#[test]
fn empty_datagram_is_a_response_and_binary_preview_is_safe() {
    assert_eq!(classify_response(Ok(0), &[0; 1024]).0, PortStatus::Open);
    let (status, detail) = classify_response(Ok(4), b"a\n\x1b\xff");
    assert_eq!(status, PortStatus::Open);
    assert_eq!(
        detail,
        "a\\n\\x1b\\xff (preview truncated; datagram may also be truncated)"
    );
}

#[test]
fn validates_before_sending_any_probes() {
    assert!(
        scan(
            ScanMode::Udp,
            "127.0.0.1".into(),
            Duration::ZERO,
            &["53"],
            2,
            |_, _| {}
        )
        .is_err()
    );
    assert!(
        scan(
            ScanMode::Udp,
            "127.0.0.1".into(),
            Duration::from_secs(1),
            &["53", "invalid"],
            2,
            |_, _| {}
        )
        .is_err()
    );
}
