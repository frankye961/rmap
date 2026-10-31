use super::{apply_http_probe_result, banner_result, read_banner};
use crate::model::{PortStatus, ScanMode, ScanResult};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

fn measured_open_http_port(port: u16) -> ScanResult {
    ScanResult {
        port,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::from_millis(17),
        error: None,
        observation: None,
        banner: None,
        service_information: None,
    }
}

#[test]
fn http_identification_reaches_scan_results_without_changing_measurements() {
    for port in [80, 8000, 8080, 8888] {
        for (server, product, version, comments) in [
            (
                Some("Apache/2.4.68 (Debian)"),
                Some("Apache"),
                Some("2.4.68"),
                Some("Debian"),
            ),
            (Some("Caddy"), Some("Caddy"), None, None),
            (None, None, None, None),
        ] {
            let mut result = measured_open_http_port(port);
            let information = super::identify::identify_http_server(server);
            let detail = server.map(|server| format!("Server: {server}"));
            apply_http_probe_result(&mut result, Ok((information, detail.clone())));
            super::identify::collect_banner(&mut result);

            assert_eq!(result.service.as_deref(), Some("http"));
            let information = result.service_information.as_ref().unwrap();
            assert_eq!(information.service.as_deref(), Some("http"));
            assert_eq!(information.product.as_deref(), product);
            assert_eq!(information.version.as_deref(), version);
            assert_eq!(information.observation.as_deref(), comments);
            assert_eq!(result.observation, detail);
            assert_eq!(result.port, port);
            assert_eq!(result.transport, ScanMode::Tcp);
            assert_eq!(result.status, PortStatus::Open);
            assert_eq!(result.elapsed, Duration::from_millis(17));
            assert!(result.error.is_none());
            assert!(result.banner.is_none());
        }
    }
}

#[test]
fn https_probe_information_reaches_results_without_changing_measured_state() {
    let header = reqwest::header::HeaderValue::from_static("Apache/2.4.68 (Debian)");
    for port in [443, 8443] {
        for server in [None, Some(&header)] {
            let mut result = measured_open_http_port(port);
            let (information, detail) = super::http::response_information(server, true);
            let expected_information = information.clone();
            apply_http_probe_result(&mut result, Ok((information, detail.clone())));
            super::identify::collect_banner(&mut result);

            assert_eq!(result.service.as_deref(), Some("https"));
            assert_eq!(
                result.service_information.as_ref(),
                Some(&expected_information)
            );
            assert_eq!(result.observation, detail);
            assert_eq!(result.port, port);
            assert_eq!(result.transport, ScanMode::Tcp);
            assert_eq!(result.status, PortStatus::Open);
            assert_eq!(result.elapsed, Duration::from_millis(17));
            assert!(result.error.is_none());
            assert!(result.banner.is_none());
        }
    }
}

#[test]
fn http_probe_failure_preserves_the_open_port_without_inventing_a_service() {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for port in [8000, 443, 8443] {
        // A deterministic request-building error exercises the shared failure path.
        // It does not claim to reproduce a TLS handshake or certificate failure.
        let error = client.head("://").build().unwrap_err();
        let mut result = measured_open_http_port(port);
        apply_http_probe_result(&mut result, Err(error));
        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.port, port);
        assert_eq!(result.elapsed, Duration::from_millis(17));
        assert!(result.service.is_none());
        assert!(result.service_information.is_none());
        assert!(result.error.is_none());
        assert!(
            result
                .observation
                .as_deref()
                .unwrap()
                .starts_with("HTTP probe failed: ")
        );
    }
}

// In-memory scripted reader; no socket or network calls are needed.
struct ScriptedRead<F>(F);

impl<F> AsyncRead for ScriptedRead<F>
where
    F: FnMut(&mut [u8]) -> io::Result<usize> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let size = (self.0)(buffer.initialize_unfilled())?;
        buffer.advance(size);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn ssh_banner_preserves_bytes_separately_from_stop_reason() {
    let data = b"SSH-2.0-OpenSSH_10.0\r\n";
    let (detail, banner) = banner_result(data, "");
    assert_eq!(detail, "");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[test]
fn received_bytes_do_not_discard_read_timeout() {
    let data = b"partial banner";
    let (detail, banner) = banner_result(data, "read timed out");
    assert_eq!(detail, "read timed out");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[tokio::test]
async fn collects_banner_across_more_than_eight_short_reads() {
    let data = b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n";
    let mut offset = 0;
    let (reason, banner) = read_banner(
        ScriptedRead(|buffer: &mut [u8]| {
            if offset == data.len() {
                return Ok(0);
            }
            buffer[0] = data[offset];
            offset += 1;
            Ok(1)
        }),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(reason, "");
    assert_eq!(banner.as_deref(), Some(data.as_slice()));
}

#[tokio::test]
async fn banner_collection_stops_at_byte_limit_even_without_a_newline() {
    let mut read_count = 0;
    let (reason, banner) = read_banner(
        ScriptedRead(|buffer: &mut [u8]| {
            read_count += 1;
            buffer.fill(b'a');
            Ok(buffer.len())
        }),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(read_count, 8);
    assert_eq!(reason, "");
    assert_eq!(banner.unwrap().len(), 512);
}

#[tokio::test]
async fn retries_interrupted_reads_without_losing_partial_banner() {
    let mut call = 0;
    let (_, banner) = read_banner(
        ScriptedRead(|buffer: &mut [u8]| {
            call += 1;
            match call {
                1 => {
                    buffer[0] = b'x';
                    Ok(1)
                }
                2 => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
                _ => {
                    buffer[0] = b'\n';
                    Ok(1)
                }
            }
        }),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(banner.as_deref(), Some(b"x\n".as_slice()));
}

#[tokio::test]
async fn async_read_timeout_keeps_partial_banner_and_stop_reason() {
    let (reader, mut writer) = tokio::io::duplex(64);
    writer.write_all(b"partial").await.unwrap();
    let (reason, banner) = read_banner(reader, Duration::from_millis(10)).await;
    assert_eq!(reason, "read timed out");
    assert_eq!(banner.as_deref(), Some(b"partial".as_slice()));
}

#[tokio::test]
async fn connection_close_keeps_collected_bytes() {
    let (reader, mut writer) = tokio::io::duplex(64);
    writer.write_all(b"partial").await.unwrap();
    drop(writer);
    let (reason, banner) = read_banner(reader, Duration::from_secs(1)).await;
    assert_eq!(reason, "peer closed connection");
    assert_eq!(banner.as_deref(), Some(b"partial".as_slice()));
}
