use super::{
    apply_http_probe_result, apply_rpc_probe_result, banner_result, collect_rpc, read_banner,
};
use crate::model::{PortStatus, ScanMode, ScanResult};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

fn measured_open_tcp_port(port: u16) -> ScanResult {
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
            let mut result = measured_open_tcp_port(port);
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
            let mut result = measured_open_tcp_port(port);
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
        let mut result = measured_open_tcp_port(port);
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

// Complete fixture reply: matching XID, accepted REPLY, empty verifier, SUCCESS.
const RPC_REPLY: [u8; 24] = [
    0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[tokio::test]
async fn rpc_collection_uses_one_xid_deadline_and_reply_limit_then_maps_the_reply() {
    let mut result = measured_open_tcp_port(111);
    let timeout = Duration::from_secs(1);
    let before = tokio::time::Instant::now();
    collect_rpc(&mut result, timeout, |xid, deadline, limit| {
        assert!(deadline >= before + timeout);
        assert!(deadline <= tokio::time::Instant::now() + timeout);
        assert_eq!(limit, 4096);
        async move {
            let mut reply = RPC_REPLY.to_vec();
            reply[..4].copy_from_slice(&xid.to_be_bytes());
            Ok(reply)
        }
    })
    .await;
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.service.as_deref(), Some("rpcbind"));
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert!(result.error.is_none());
    assert!(result.banner.is_none());
    assert!(
        result
            .service_information
            .as_ref()
            .unwrap()
            .version
            .is_none()
    );
}

#[tokio::test]
async fn rpc_collection_preserves_open_measurements_when_the_exchange_fails() {
    let mut result = measured_open_tcp_port(111);
    collect_rpc(&mut result, Duration::from_secs(1), |_, _, _| async {
        Err("RPC connection failed: fixture refusal".into())
    })
    .await;
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert!(result.error.is_none());
    assert!(result.service.is_none());
    assert!(result.service_information.is_none());
    assert_eq!(
        result.observation.as_deref(),
        Some("RPC probe failed: RPC connection failed: fixture refusal")
    );
}

#[tokio::test]
async fn rpc_collection_rejects_a_reply_with_the_wrong_request_xid() {
    let mut result = measured_open_tcp_port(111);
    collect_rpc(
        &mut result,
        Duration::from_secs(1),
        |xid, _, _| async move {
            let mut reply = RPC_REPLY.to_vec();
            reply[..4].copy_from_slice(&xid.wrapping_add(1).to_be_bytes());
            Ok(reply)
        },
    )
    .await;
    assert_eq!(result.status, PortStatus::Open);
    assert!(result.service.is_none());
    assert!(
        result
            .observation
            .as_deref()
            .unwrap()
            .contains("transaction ID does not match")
    );
}

#[tokio::test]
async fn rpc_collection_does_not_call_the_exchange_for_other_ports_states_or_modes() {
    for (port, transport, status) in [
        (80, ScanMode::Tcp, PortStatus::Open),
        (2049, ScanMode::Tcp, PortStatus::Open),
        (111, ScanMode::Udp, PortStatus::Open),
        (111, ScanMode::Syn, PortStatus::Open),
        (111, ScanMode::Tcp, PortStatus::Closed),
        (111, ScanMode::Tcp, PortStatus::Filtered),
        (111, ScanMode::Tcp, PortStatus::Unknown),
    ] {
        let mut result = measured_open_tcp_port(port);
        result.transport = transport;
        result.status = status;
        collect_rpc(&mut result, Duration::from_secs(1), |_, _, _| async {
            panic!("RPC exchange must not run for this result")
        })
        .await;
        assert_eq!(result.transport, transport);
        assert_eq!(result.status, status);
        assert!(result.service.is_none());
        assert!(result.observation.is_none());
    }
}

#[test]
fn rpc_reply_reaches_scan_results_without_changing_connection_evidence() {
    let mut result = measured_open_tcp_port(111);
    let banner = b"partial passive data".to_vec();
    result.banner = Some(banner.clone());
    result.observation = Some("read timed out".into());
    apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);

    assert_eq!(result.service.as_deref(), Some("rpcbind"));
    let information = result.service_information.as_ref().unwrap();
    assert_eq!(information.transport, ScanMode::Tcp);
    assert!(information.product.is_none());
    assert!(information.version.is_none());
    assert_eq!(result.port, 111);
    assert_eq!(result.transport, ScanMode::Tcp);
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert_eq!(result.banner, Some(banner));
    assert!(result.error.is_none());
    let observation = result.observation.as_deref().unwrap();
    assert!(observation.starts_with("read timed out; "));
    assert!(observation.contains("portmapper protocol version 2"));
}

#[test]
fn rpc_probe_failure_preserves_open_state_and_existing_identification() {
    let mut unsuccessful = RPC_REPLY;
    unsuccessful[23] = 1;
    for response in [
        Err("read timed out".to_string()),
        Ok(&[][..]),
        Ok(&unsuccessful[..]),
    ] {
        let mut result = measured_open_tcp_port(111);
        let existing = super::identify::identify_http_server(Some("Caddy"));
        super::apply_service_information(&mut result, existing.clone());
        result.observation = Some("passive read finished".into());
        result.banner = Some(b"original bytes".to_vec());
        apply_rpc_probe_result(&mut result, response, 0x12345678);

        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.port, 111);
        assert_eq!(result.transport, ScanMode::Tcp);
        assert_eq!(result.elapsed, Duration::from_millis(17));
        assert!(result.error.is_none());
        assert_eq!(result.service.as_deref(), Some("http"));
        assert_eq!(result.service_information, Some(existing));
        assert_eq!(result.banner.as_deref(), Some(b"original bytes".as_slice()));
        assert!(
            result
                .observation
                .as_deref()
                .unwrap()
                .starts_with("passive read finished; RPC probe failed: ")
        );
    }
}

#[test]
fn rpc_probe_cannot_identify_a_reply_for_another_transaction() {
    let mut result = measured_open_tcp_port(111);
    apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345679);
    assert_eq!(result.status, PortStatus::Open);
    assert!(result.service.is_none());
    assert!(result.service_information.is_none());
    assert!(
        result
            .observation
            .as_deref()
            .unwrap()
            .contains("transaction ID does not match")
    );
}

#[test]
fn rpc_probe_failure_keeps_unidentified_ports_open_without_guessing_a_service() {
    for observation in [None, Some(String::new())] {
        let mut result = measured_open_tcp_port(111);
        result.observation = observation;
        apply_rpc_probe_result(&mut result, Err("read timed out".into()), 0x12345678);
        assert_eq!(result.status, PortStatus::Open);
        assert!(result.error.is_none());
        assert!(result.service.is_none());
        assert!(result.service_information.is_none());
        assert_eq!(
            result.observation.as_deref(),
            Some("RPC probe failed: read timed out")
        );
    }
}

#[test]
fn rpc_probe_result_ignores_non_candidates_and_non_open_tcp_connect_results() {
    for (port, transport, status) in [
        (80, ScanMode::Tcp, PortStatus::Open),
        (2049, ScanMode::Tcp, PortStatus::Open),
        (111, ScanMode::Udp, PortStatus::Open),
        (111, ScanMode::Syn, PortStatus::Open),
        (111, ScanMode::Tcp, PortStatus::Closed),
        (111, ScanMode::Tcp, PortStatus::Filtered),
        (111, ScanMode::Tcp, PortStatus::Unknown),
    ] {
        let mut result = measured_open_tcp_port(port);
        result.transport = transport;
        result.status = status;
        result.observation = Some("original observation".into());
        apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
        assert_eq!(result.port, port);
        assert_eq!(result.transport, transport);
        assert_eq!(result.status, status);
        assert_eq!(result.observation.as_deref(), Some("original observation"));
        assert!(result.service.is_none());
        assert!(result.service_information.is_none());
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
