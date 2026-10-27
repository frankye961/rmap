use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{Method, header::HeaderValue};

use super::{client, head_request, is_http_candidate, server_observation};

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
