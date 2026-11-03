use std::time::Duration;

use super::format_result;
use crate::model::{PortStatus, ScanMode, ScanResult};

#[test]
fn displays_mapped_rpc_information_without_a_fabricated_software_version() {
    let information = crate::mapper::service_information::map_portmapper_service();
    let mut result = ScanResult {
        port: 111,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::from_millis(17),
        error: None,
        observation: information.observation.clone(),
        banner: None,
        service_information: None,
        rpc_mappings: None,
    };
    crate::mapper::service_information::apply_service_information(&mut result, information);
    let line = format_result(&result);
    assert!(line.starts_with("111/tcp"));
    assert!(line.contains("open"));
    assert!(line.contains("rpcbind"));
    assert!(line.contains("17.00 ms"));
    assert!(line.contains("portmapper protocol version 2"));
    let information = result.service_information.as_ref().unwrap();
    assert!(information.product.is_none());
    assert!(information.version.is_none());
}

#[test]
fn syn_cleanup_diagnostic_is_visible_without_erasing_the_open_state() {
    let result = crate::mapper::syn::map_syn_result(
        "192.0.2.21:80".parse().unwrap(),
        PortStatus::Open,
        Duration::from_millis(20),
        None,
        Some("Matching TCP SYN/ACK received; RST cleanup failed: timed out".into()),
    );
    let line = format_result(&result);
    assert!(line.starts_with("80/tcp"));
    assert!(line.contains("open"));
    assert!(line.contains("RST cleanup failed"));
    assert!(result.banner.is_none());
    assert!(result.service_information.is_none());
}

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
        rpc_mappings: None,
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
        rpc_mappings: None,
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
        rpc_mappings: None,
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
        rpc_mappings: None,
    })
    .collect()
}

#[test]
fn advertised_mapping_table_does_not_add_measured_open_ports() {
    let mut results = measured_results();
    results[0].port = 111;
    results[0].transport = ScanMode::Tcp;
    results[0].service = Some("rpcbind".into());
    results[0].rpc_mappings = Some(vec![
        crate::model::rpc::RpcMapping {
            program: 100000,
            program_version: 2,
            protocol: 6,
            port: 111,
        },
        crate::model::rpc::RpcMapping {
            program: 100000,
            program_version: 2,
            protocol: 17,
            port: 111,
        },
        crate::model::rpc::RpcMapping {
            program: 100123,
            program_version: 7,
            protocol: 250,
            port: 2049,
        },
    ]);
    let mut output = Vec::new();
    super::write_results(&mut output, "192.0.2.21", &results, true).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("RPC registrations advertised by 111/tcp"));
    assert!(output.contains("connectivity has not been tested by enumeration"));
    assert!(output.contains("PROGRAM"));
    assert!(output.contains("TRANSPORT"));
    for value in ["100000", "100123", "TCP", "UDP", "IP(250)", "2049"] {
        assert!(output.contains(value));
    }
    assert!(output.contains("Open ports shown: 1; ports scanned: 5."));
    assert!(!output.contains("2049/tcp"));
    assert_eq!(results.len(), 5);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status == PortStatus::Open)
            .count(),
        1
    );
}

#[test]
fn report_distinguishes_an_empty_dump_from_no_successful_enumeration() {
    let mut results = measured_results();
    results[0].port = 111;
    results[0].transport = ScanMode::Tcp;
    results[0].service = Some("rpcbind".into());
    let mut output = Vec::new();
    super::write_results(&mut output, "192.0.2.21", &results, false).unwrap();
    assert!(
        !String::from_utf8(output)
            .unwrap()
            .contains("RPC registrations")
    );

    results[0].rpc_mappings = Some(Vec::new());
    let mut output = Vec::new();
    super::write_results(&mut output, "192.0.2.21", &results, false).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("RPC registrations advertised by 111/tcp"));
    assert!(output.contains("No registrations advertised."));
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
    assert!(output.contains("No open ports confirmed; 1 of 4 probes were undetermined."));
    assert!(output.contains("Undetermined probes: 1."));
    assert!(!output.contains("2/udp"));
}

#[test]
fn open_only_report_exposes_local_failures_without_printing_non_open_rows() {
    let results = [80, 443].map(|port| {
        crate::mapper::syn::map_syn_result(
            std::net::SocketAddr::from(([192, 0, 2, 21], port)),
            PortStatus::Unknown,
            Duration::ZERO,
            Some("Cannot prepare raw TCP socket: Too many open files".into()),
            None,
        )
    });
    let mut output = Vec::new();
    super::write_results(&mut output, "192.0.2.21", &results, true).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("No open ports confirmed; 2 of 2 probes were undetermined."));
    assert!(output.contains("Too many open files"));
    assert!(!output.contains("80/tcp"));
    assert!(!output.contains("443/tcp"));
}

#[test]
fn open_only_report_without_local_failures_keeps_the_empty_scan_message() {
    let mut output = Vec::new();
    let results = measured_results();
    super::write_results(&mut output, "192.0.2.21", &results[1..4], true).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("No open ports found among 3 scanned ports."));
    assert!(!output.contains("Undetermined probes:"));
}
