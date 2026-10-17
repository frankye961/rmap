use rig::completion::{CompletionError, PromptError};
use rig::http_client::Error as HttpError;

use super::describe_ai_error;

#[test]
fn reports_provider_status_without_echoing_response_text() {
    let error = PromptError::CompletionError(CompletionError::HttpError(
        HttpError::InvalidStatusCodeWithMessage(
            "401".parse().unwrap(),
            "provider response may contain sensitive text".into(),
        ),
    ));
    let message = describe_ai_error(&error);
    assert!(message.contains("HTTP 401"));
    assert!(!message.contains("sensitive text"));
}

#[test]
fn reports_json_location_without_response_body() {
    let parse_error = serde_json::from_str::<String>("null").unwrap_err();
    let error = PromptError::CompletionError(CompletionError::JsonError(parse_error));
    let message = describe_ai_error(&error);
    assert!(message.contains("line 1, column 4"));
    assert!(!message.contains("null"));
}

#[test]
fn udp_observations_keep_their_transport() {
    use crate::model::{PortStatus, ScanMode, ScanResult};
    use std::time::Duration;

    let result = ScanResult {
        port: 53,
        transport: ScanMode::Udp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: Some("response".into()),
        banner: None,
    };
    let prompt = super::build_prompt(&[result], &[]);
    assert!(prompt.contains("53/udp"));
    assert!(!prompt.contains("53/tcp"));
}

#[test]
fn closed_and_uncertain_ports_are_still_measured_observations() {
    use crate::model::{PortStatus, ScanMode, ScanResult};
    use std::time::Duration;

    let results: Vec<_> = [(80, PortStatus::Closed), (21, PortStatus::OpenOrFiltered)]
        .into_iter()
        .map(|(port, status)| ScanResult {
            port,
            transport: ScanMode::Udp,
            status,
            service: None,
            elapsed: Duration::from_secs(1),
            error: None,
            observation: Some("probe outcome".into()),
            banner: None,
        })
        .collect();
    let prompt = super::build_prompt(&results, &[]);
    assert!(prompt.contains("80/udp: state Closed"));
    assert!(prompt.contains("21/udp: state OpenOrFiltered"));
    assert!(!prompt.contains("Do not name any CVE"));
}

#[test]
fn research_reads_banner_beyond_console_preview_and_keeps_stop_reason() {
    use crate::model::{PortStatus, ScanMode, ScanResult};
    use std::time::Duration;

    let mut bytes = vec![b' '; 70];
    bytes.extend_from_slice(b"220 (vsFTPd 3.0.5)");
    let result = ScanResult {
        port: 21,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: Some("read timed out".into()),
        banner: Some(bytes),
    };
    let prompt = super::build_prompt(&[result], &[]);
    assert!(prompt.contains("vsFTPd 3.0.5"));
    assert!(prompt.contains("Read outcome: read timed out"));
    assert!(!prompt.contains("preview truncated"));
}
