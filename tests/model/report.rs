use std::time::Duration;

use super::format_result;
use crate::model::{PortStatus, ScanMode, ScanResult};

#[test]
fn reports_transport_uncertainty_and_elapsed_time() {
    let mut result = ScanResult {
        port: 53,
        transport: ScanMode::Udp,
        status: PortStatus::OpenOrFiltered,
        service: None,
        elapsed: Duration::from_millis(1000),
        error: None,
        observation: Some("no response".into()),
        banner: None,
        service_information: None,
    };
    let line = format_result(&result);
    assert!(line.starts_with("53/udp"));
    assert!(line.contains("open|filtered"));
    assert!(line.contains("1000.00 ms"));
    assert!(line.ends_with("no response"));
    result.transport = ScanMode::Tcp;
    result.status = PortStatus::Closed;
    assert!(format_result(&result).starts_with("53/tcp"));
}

#[test]
fn shows_safe_banner_preview_and_preserves_full_bytes_and_stop_reason() {
    let mut bytes = b"\x1bSSH-2.0-".to_vec();
    bytes.extend_from_slice(&[b'x'; 80]);
    bytes.extend_from_slice(b"\r\n");
    let result = ScanResult {
        port: 22,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: Some("ssh".into()),
        elapsed: Duration::ZERO,
        error: None,
        observation: Some("read timed out".into()),
        banner: Some(bytes.clone()),
        service_information: None,
    };
    let line = format_result(&result);
    assert!(line.contains("\\x1bSSH-2.0-"));
    assert!(!line.contains('\x1b'));
    assert!(line.ends_with("(preview truncated) (read timed out)"));
    assert_eq!(result.banner.as_deref(), Some(bytes.as_slice()));
}

#[test]
fn strips_banner_line_ending_without_quotes_or_empty_reason() {
    let result = ScanResult {
        port: 22,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: Some("ssh".into()),
        elapsed: Duration::ZERO,
        error: None,
        observation: Some(String::new()),
        banner: Some(b"SSH-2.0-OpenSSH_10.0\r\n".to_vec()),
        service_information: None,
    };
    assert!(format_result(&result).ends_with("SSH-2.0-OpenSSH_10.0"));
}
