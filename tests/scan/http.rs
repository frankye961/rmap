use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{Method, header::HeaderValue};

use super::{
    client, head_request, is_http_candidate, is_https_candidate, probe_request,
    response_information, server_observation,
};
use crate::model::ScanMode;

#[test]
fn selects_the_supported_plain_http_candidate_ports() {
    for port in [80, 8000, 8080, 8888] {
        assert!(is_http_candidate(port), "HTTP candidate {port} was skipped");
    }
}

#[test]
fn does_not_select_other_services_tls_ports_or_neighboring_ports() {
    for port in [
        0,
        21,
        22,
        79,
        81,
        443,
        7999,
        8001,
        8079,
        8081,
        8443,
        8887,
        8889,
        u16::MAX,
    ] {
        assert!(!is_http_candidate(port), "Unexpected HTTP candidate {port}");
    }
}

#[test]
fn selects_only_the_supported_https_candidate_ports() {
    for port in [443, 8443] {
        assert!(is_https_candidate(port));
        assert!(!is_http_candidate(port));
    }
    for port in [0, 22, 80, 442, 444, 8000, 8080, 8442, 8444, 8888, u16::MAX] {
        assert!(
            !is_https_candidate(port),
            "Unexpected HTTPS candidate {port}"
        );
    }
}

#[test]
fn builds_head_request_for_target() {
    let client = client(Duration::from_secs(2)).unwrap();
    for port in [80, 8000, 8080, 8888] {
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        let request = head_request(&client, target).unwrap();

        assert_eq!(request.method(), Method::HEAD);
        assert_eq!(request.url().scheme(), "http");
        assert_eq!(request.url().host_str(), Some("127.0.0.1"));
        assert_eq!(request.url().port_or_known_default(), Some(port));
        assert_eq!(request.url().path(), "/");
        assert!(request.body().is_none());
    }
}

#[test]
fn selects_head_request_scheme_and_destination_for_each_candidate() {
    let client = client(Duration::from_secs(2)).unwrap();
    for (port, scheme) in [
        (80, "http"),
        (8000, "http"),
        (8080, "http"),
        (8888, "http"),
        (443, "https"),
        (8443, "https"),
    ] {
        let target = SocketAddr::from(([192, 0, 2, 21], port));
        let request = probe_request(&client, target).unwrap();
        assert_eq!(request.method(), Method::HEAD);
        assert_eq!(request.url().scheme(), scheme);
        assert_eq!(request.url().host_str(), Some("192.0.2.21"));
        assert_eq!(request.url().port_or_known_default(), Some(port));
        assert_eq!(request.url().path(), "/");
        assert!(request.body().is_none());
    }
}

#[test]
fn displays_server_header_without_status_or_byte_count() {
    let server = HeaderValue::from_static("Apache/2.4.68 (Debian)");
    assert_eq!(
        server_observation(Some(&server)).as_deref(),
        Some("Server: Apache/2.4.68 (Debian)")
    );
    assert_eq!(server_observation(None), None);
}

#[test]
fn http_response_supplies_structured_software_and_keeps_the_display_detail() {
    let server = HeaderValue::from_static("Apache/2.4.68 (Debian)");
    let (information, detail) = response_information(Some(&server), false);
    assert_eq!(information.service.as_deref(), Some("http"));
    assert_eq!(information.product.as_deref(), Some("Apache"));
    assert_eq!(information.version.as_deref(), Some("2.4.68"));
    assert_eq!(information.observation.as_deref(), Some("Debian"));
    assert_eq!(detail.as_deref(), Some("Server: Apache/2.4.68 (Debian)"));
}

#[test]
fn missing_or_undecodable_server_header_still_identifies_http() {
    let invalid_text = HeaderValue::from_bytes(b"Apache/\xff").unwrap();
    for server in [None, Some(&invalid_text)] {
        let (information, _) = response_information(server, false);
        assert_eq!(information.service.as_deref(), Some("http"));
        assert!(information.product.is_none());
        assert!(information.version.is_none());
        assert!(information.observation.is_none());
    }
    assert!(response_information(None, false).1.is_none());
    assert_eq!(
        response_information(Some(&invalid_text), false)
            .1
            .as_deref(),
        Some("Server: Apache/\\xff")
    );
}

#[test]
fn parses_the_original_header_before_truncating_its_console_preview() {
    let comment = "d".repeat(100);
    let header = format!("Apache/2.4.68 ({comment})");
    let server = HeaderValue::from_str(&header).unwrap();
    let (information, detail) = response_information(Some(&server), false);
    assert_eq!(information.observation.as_deref(), Some(comment.as_str()));
    assert_eq!(detail.unwrap(), format!("Server: {}", &header[..64]));
}

#[test]
fn https_response_keeps_structured_software_and_tcp_transport() {
    let server = HeaderValue::from_static("Apache/2.4.68 (Debian)");
    let (information, detail) = response_information(Some(&server), true);
    assert_eq!(information.transport, ScanMode::Tcp);
    assert_eq!(information.service.as_deref(), Some("https"));
    assert_eq!(information.product.as_deref(), Some("Apache"));
    assert_eq!(information.version.as_deref(), Some("2.4.68"));
    assert_eq!(information.observation.as_deref(), Some("Debian"));
    assert_eq!(detail.as_deref(), Some("Server: Apache/2.4.68 (Debian)"));
}

#[test]
fn missing_empty_malformed_or_undecodable_header_does_not_erase_https() {
    let empty = HeaderValue::from_static("");
    let malformed = HeaderValue::from_static("Apache/2.4.68/extra");
    let undecodable = HeaderValue::from_bytes(b"Apache/\xff").unwrap();
    for server in [None, Some(&empty), Some(&malformed), Some(&undecodable)] {
        let (information, _) = response_information(server, true);
        assert_eq!(information.transport, ScanMode::Tcp);
        assert_eq!(information.service.as_deref(), Some("https"));
        assert!(information.product.is_none());
        assert!(information.version.is_none());
        assert!(information.observation.is_none());
    }
    assert!(response_information(None, true).1.is_none());
}

#[test]
fn https_label_follows_the_selected_request_without_a_network_call() {
    let client = client(Duration::from_secs(1)).unwrap();
    let server = HeaderValue::from_static("Caddy");
    for (port, service) in [(80, "http"), (443, "https"), (8443, "https")] {
        let request = probe_request(&client, SocketAddr::from(([192, 0, 2, 21], port))).unwrap();
        // This fixture represents a response after successful request execution.
        let (information, _) =
            response_information(Some(&server), request.url().scheme() == "https");
        assert_eq!(information.service.as_deref(), Some(service));
        assert_eq!(information.product.as_deref(), Some("Caddy"));
        assert!(information.version.is_none());
    }
}
