use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{Method, header::HeaderValue};

use super::{client, head_request, server_observation};

#[test]
fn builds_head_request_for_target() {
    let client = client(Duration::from_secs(2)).unwrap();
    let target: SocketAddr = "127.0.0.1:80".parse().unwrap();
    let request = head_request(&client, target).unwrap();

    assert_eq!(request.method(), Method::HEAD);
    assert_eq!(request.url().as_str(), "http://127.0.0.1/");
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
