use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{Method, header::HeaderValue};

use super::{client, head_request, is_http_candidate, response_information, server_observation};

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
    let (information, detail) = response_information(Some(&server));
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
        let (information, _) = response_information(server);
        assert_eq!(information.service.as_deref(), Some("http"));
        assert!(information.product.is_none());
        assert!(information.version.is_none());
        assert!(information.observation.is_none());
    }
    assert!(response_information(None).1.is_none());
    assert_eq!(
        response_information(Some(&invalid_text)).1.as_deref(),
        Some("Server: Apache/\\xff")
    );
}

#[test]
fn parses_the_original_header_before_truncating_its_console_preview() {
    let comment = "d".repeat(100);
    let header = format!("Apache/2.4.68 ({comment})");
    let server = HeaderValue::from_str(&header).unwrap();
    let (information, detail) = response_information(Some(&server));
    assert_eq!(information.observation.as_deref(), Some(comment.as_str()));
    assert_eq!(detail.unwrap(), format!("Server: {}", &header[..64]));
}
