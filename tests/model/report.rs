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

fn measured_results() -> Vec<ScanResult> {
    [
        PortStatus::Open,
        PortStatus::Closed,
        PortStatus::Filtered,
        PortStatus::OpenOrFiltered,
        PortStatus::Unknown,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, status)| ScanResult {
        port: index as u16 + 1,
        transport: ScanMode::Udp,
        status,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: None,
        banner: None,
        service_information: None,
    })
    .collect()
}

#[test]
fn only_open_onlys_hide_non_open_rows_without_changing_measurements() {
    let results = measured_results();
    for open_only in [false, true] {
        let mut output = Vec::new();
        super::write_results(&mut output, "192.0.2.21", &results, open_only).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("1/udp"));
        for port in 2..=5 {
            assert_eq!(output.contains(&format!("{port}/udp")), !open_only);
        }
        assert_eq!(output.contains("open|filtered ="), !open_only);
        assert_eq!(
            output.contains("Open ports shown: 1; ports scanned: 5."),
            open_only
        );
    }
    assert_eq!(results.len(), 5);
    assert_eq!(results[3].status, PortStatus::OpenOrFiltered);
}

#[test]
fn open_only_without_open_ports_prints_an_explicit_message() {
    let results = measured_results();
    let mut output = Vec::new();
    super::write_results(&mut output, "192.0.2.21", &results[1..], true).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("No open ports found among 4 scanned ports."));
    assert!(!output.contains("2/udp"));
}
