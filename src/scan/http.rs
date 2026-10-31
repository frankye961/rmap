//! HTTP and HTTPS response probes for open TCP candidate ports.

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{
    Client, Request,
    header::{HeaderValue, SERVER},
    redirect::Policy,
};

use super::identify;
use crate::model::service_information::ServiceInformation;
use crate::utils::banner::escape_bytes;

/// Decide whether an open port is a candidate for a plain HTTP probe.
///
/// Select a probe using the port as a hint; the response establishes the service.
pub(super) fn is_http_candidate(_port: u16) -> bool {
    matches!(_port, 80 | 8000 | 8080 | 8888)
}

/// Select a TLS-wrapped HTTP probe; the port alone does not identify HTTPS.
pub(super) fn is_https_candidate(_port: u16) -> bool {
    matches!(_port, 443 | 8443)
}

fn client(timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .no_proxy()
        .build()
}

fn https_head_request(client: &Client, target: SocketAddr) -> Result<Request, reqwest::Error> {
    client.head(format!("https://{target}/")).build()
}

fn head_request(client: &Client, target: SocketAddr) -> Result<Request, reqwest::Error> {
    client.head(format!("http://{target}/")).build()
}

/// Select the request for a candidate already chosen by the TCP scanner.
fn probe_request(client: &Client, target: SocketAddr) -> Result<Request, reqwest::Error> {
    match is_http_candidate(target.port()) {
        true => head_request(client, target),
        false => https_head_request(client, target),
    }
}

fn server_observation(server: Option<&HeaderValue>) -> Option<String> {
    server.map(|server| {
        let server_preview = escape_bytes(server.as_bytes(), 64);
        format!("Server: {server_preview}")
    })
}

/// Interpret an HTTP response after execution succeeds, retaining its request scheme.
pub(super) fn response_information(
    server: Option<&HeaderValue>,
    is_https: bool,
) -> (ServiceInformation, Option<String>) {
    let mut information =
        identify::identify_http_server(server.and_then(|value| value.to_str().ok()));
    if is_https {
        information.service = Some("https".to_string());
    }
    (information, server_observation(server))
}

pub async fn probe(
    target: SocketAddr,
    timeout: Duration,
) -> Result<(ServiceInformation, Option<String>), reqwest::Error> {
    let client = client(timeout)?;
    let request = probe_request(&client, target)?;
    let is_https = request.url().scheme() == "https";
    let response = client.execute(request).await?;
    Ok(response_information(
        response.headers().get(SERVER),
        is_https,
    ))
}

#[cfg(test)]
#[path = "../../tests/scan/http.rs"]
mod tests;
