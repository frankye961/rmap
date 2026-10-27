//! HTTP response probe for an open TCP port.

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{
    Client, Request,
    header::{HeaderValue, SERVER},
    redirect::Policy,
};

use crate::utils::banner::escape_bytes;

/// Decide whether an open port is a candidate for a plain HTTP probe.
///
/// Select a probe using the port as a hint; the response establishes the service.
pub(super) fn is_http_candidate(_port: u16) -> bool {
    matches!(_port, 80 | 8000 | 8080 | 8888)
}

fn client(timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .no_proxy()
        .build()
}

fn head_request(client: &Client, target: SocketAddr) -> Result<Request, reqwest::Error> {
    client.head(format!("http://{target}/")).build()
}

fn server_observation(server: Option<&HeaderValue>) -> Option<String> {
    server.map(|server| {
        let server_preview = escape_bytes(server.as_bytes(), 64);
        format!("Server: {server_preview}")
    })
}

pub async fn probe(
    target: SocketAddr,
    timeout: Duration,
) -> Result<Option<String>, reqwest::Error> {
    let client = client(timeout)?;
    let request = head_request(&client, target)?;
    let response = client.execute(request).await?;
    Ok(server_observation(response.headers().get(SERVER)))
}

#[cfg(test)]
#[path = "../../tests/scan/http.rs"]
mod tests;
