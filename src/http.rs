//! HTTP response probe for an open TCP port.

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{
    Client, Request,
    header::{HeaderValue, SERVER},
    redirect::Policy,
};

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
        let server_preview: String = server
            .as_bytes()
            .iter()
            .take(64)
            .flat_map(|byte| std::ascii::escape_default(*byte))
            .map(char::from)
            .collect();
        format!("Server: {server_preview}")
    })
}

#[tokio::main(flavor = "current_thread")]
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
mod tests {
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
}
