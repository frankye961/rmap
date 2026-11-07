use super::{
    apply_http_probe_result, apply_rpc_dump_result, apply_rpc_probe_result, banner_result,
    collect_nfs, collect_rpc, collect_rpc_dump, collect_smb, read_banner,
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
        rpc_mappings: None,
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
async fn nfs_collection_identifies_version_three_and_preserves_connection_evidence() {
    let mut result = measured_open_tcp_port(2049);
    result.observation = Some("earlier read stopped".into());
    result.banner = Some(b"earlier bytes".to_vec());
    let timeout = Duration::from_secs(1);
    let before = tokio::time::Instant::now();
    collect_nfs(&mut result, timeout, |xid, deadline, limit| {
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
    assert_eq!(result.service.as_deref(), Some("nfs"));
    let information = result.service_information.as_ref().unwrap();
    assert_eq!(information.transport, ScanMode::Tcp);
    assert!(information.product.is_none());
    assert!(information.version.is_none());
    assert!(
        information
            .observation
            .as_deref()
            .unwrap()
            .contains("NFS protocol version 3")
    );
    assert_eq!(result.port, 2049);
    assert_eq!(result.transport, ScanMode::Tcp);
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert!(result.error.is_none());
    assert!(result.rpc_mappings.is_none());
    assert_eq!(result.banner.as_deref(), Some(b"earlier bytes".as_slice()));
    assert!(
        result
            .observation
            .as_deref()
            .unwrap()
            .starts_with("earlier read stopped; ")
    );
}

#[tokio::test]
async fn nfs_probe_failures_preserve_existing_identification_and_open_measurements() {
    for failure in ["io", "truncated", "xid", "payload", "version_mismatch"] {
        let mut result = measured_open_tcp_port(2049);
        let previous = crate::mapper::service_information::map_tcp_service("rpc", None, None, None);
        super::apply_service_information(&mut result, previous.clone());
        result.observation = Some("earlier observation".into());
        result.banner = Some(b"earlier bytes".to_vec());
        collect_nfs(
            &mut result,
            Duration::from_secs(1),
            |xid, _, _| async move {
                if failure == "io" {
                    return Err("fixture NFS timeout".into());
                }
                if failure == "truncated" {
                    return Ok(Vec::new());
                }
                let mut reply = RPC_REPLY.to_vec();
                let response_xid = if failure == "xid" {
                    xid.wrapping_add(1)
                } else {
                    xid
                };
                reply[..4].copy_from_slice(&response_xid.to_be_bytes());
                if failure == "payload" {
                    reply.extend_from_slice(&[0; 4]);
                }
                if failure == "version_mismatch" {
                    reply[23] = 2;
                }
                Ok(reply)
            },
        )
        .await;
        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.service.as_deref(), Some("rpc"));
        assert_eq!(result.service_information, Some(previous));
        assert_eq!(result.elapsed, Duration::from_millis(17));
        assert!(result.error.is_none());
        assert_eq!(result.banner.as_deref(), Some(b"earlier bytes".as_slice()));
        assert!(
            result
                .observation
                .as_deref()
                .unwrap()
                .starts_with("earlier observation; NFS probe failed: ")
        );
    }
}

#[tokio::test]
async fn nfs_candidate_port_alone_does_not_establish_identity_on_probe_failure() {
    let mut result = measured_open_tcp_port(2049);
    collect_nfs(&mut result, Duration::from_secs(1), |_, _, _| async {
        Err("fixture read timeout".into())
    })
    .await;
    assert_eq!(result.status, PortStatus::Open);
    assert!(result.service.is_none());
    assert!(result.service_information.is_none());
    assert_eq!(
        result.observation.as_deref(),
        Some("NFS probe failed: fixture read timeout")
    );
    assert!(result.error.is_none());
}

#[tokio::test]
async fn nfs_collection_skips_other_ports_states_and_scan_modes() {
    for (port, transport, status) in [
        (111, ScanMode::Tcp, PortStatus::Open),
        (80, ScanMode::Tcp, PortStatus::Open),
        (2050, ScanMode::Tcp, PortStatus::Open),
        (2049, ScanMode::Udp, PortStatus::Open),
        (2049, ScanMode::Syn, PortStatus::Open),
        (2049, ScanMode::Tcp, PortStatus::Closed),
        (2049, ScanMode::Tcp, PortStatus::Filtered),
        (2049, ScanMode::Tcp, PortStatus::Unknown),
    ] {
        let mut result = measured_open_tcp_port(port);
        result.transport = transport;
        result.status = status;
        collect_nfs(&mut result, Duration::from_secs(1), |_, _, _| async {
            panic!("NFS exchange must not run for this result")
        })
        .await;
        assert_eq!(result.transport, transport);
        assert_eq!(result.status, status);
        assert!(result.service.is_none());
        assert!(result.observation.is_none());
    }
}

fn smb_reply_fixture(message_id: u64, dialect: u16) -> Vec<u8> {
    let mut reply = vec![0; 128];
    reply[..8].copy_from_slice(&[0xfe, 0x53, 0x4d, 0x42, 64, 0, 0, 0]);
    reply[14..20].copy_from_slice(&[7, 0, 1, 0, 0, 0]);
    reply[24..32].copy_from_slice(&message_id.to_le_bytes());
    reply[64..68].copy_from_slice(&[65, 0, 1, 0]);
    reply[68..70].copy_from_slice(&dialect.to_le_bytes());
    reply[92..104].copy_from_slice(&[0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0]);
    reply
}

#[tokio::test]
async fn smb_collection_uses_bounded_negotiation_and_preserves_connection_evidence() {
    for dialect in [0x0202, 0x0210] {
        let mut result = measured_open_tcp_port(445);
        result.observation = Some("earlier observation".into());
        result.banner = Some(b"earlier bytes".to_vec());
        let timeout = Duration::from_secs(1);
        let before = tokio::time::Instant::now();
        collect_smb(&mut result, timeout, |message_id, guid, deadline, limit| {
            assert_eq!(message_id, 0);
            assert_eq!(guid, super::smb::client_guid().unwrap());
            assert!(deadline >= before + timeout);
            assert!(deadline <= tokio::time::Instant::now() + timeout);
            assert_eq!(limit, 4096);
            async move { Ok(smb_reply_fixture(message_id, dialect)) }
        })
        .await;
        super::identify::collect_banner(&mut result);
        assert_eq!(result.service.as_deref(), Some("smb"));
        let information = result.service_information.as_ref().unwrap();
        assert_eq!(information.transport, ScanMode::Tcp);
        assert!(information.product.is_none());
        assert!(information.version.is_none());
        assert_eq!(
            information.observation,
            Some(format!(
                "SMB protocol dialect {dialect:#06x} negotiated successfully"
            )),
        );
        assert_eq!(result.port, 445);
        assert_eq!(result.transport, ScanMode::Tcp);
        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.elapsed, Duration::from_millis(17));
        assert!(result.error.is_none());
        assert!(result.rpc_mappings.is_none());
        assert_eq!(result.banner.as_deref(), Some(b"earlier bytes".as_slice()));
        assert!(
            result
                .observation
                .as_deref()
                .unwrap()
                .starts_with("earlier observation; SMB")
        );
    }
}

#[tokio::test]
async fn smb_failures_keep_open_measurements_and_previous_identification() {
    for failure in [
        "io",
        "header",
        "truncated",
        "id",
        "status",
        "dialect",
        "buffer",
    ] {
        let mut result = measured_open_tcp_port(445);
        let previous =
            crate::mapper::service_information::map_tcp_service("prior", None, None, None);
        super::apply_service_information(&mut result, previous.clone());
        result.observation = Some("earlier observation".into());
        result.banner = Some(b"earlier bytes".to_vec());
        result.rpc_mappings = Some(vec![advertised_mapping()]);
        collect_smb(
            &mut result,
            Duration::from_secs(1),
            |message_id, _, _, _| async move {
                if failure == "io" {
                    return Err("fixture SMB timeout".into());
                }
                let mut reply = smb_reply_fixture(message_id, 0x0210);
                match failure {
                    "header" => reply[0] = 0xff,
                    "truncated" => reply.truncate(127),
                    "id" => reply[24] = 1,
                    "status" => reply[8] = 1,
                    "dialect" => reply[68..70].copy_from_slice(&0x0311_u16.to_le_bytes()),
                    "buffer" => reply[122] = 1,
                    _ => unreachable!(),
                }
                Ok(reply)
            },
        )
        .await;
        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.service.as_deref(), Some("prior"));
        assert_eq!(result.service_information, Some(previous));
        assert_eq!(result.elapsed, Duration::from_millis(17));
        assert!(result.error.is_none());
        assert_eq!(result.banner.as_deref(), Some(b"earlier bytes".as_slice()));
        assert_eq!(result.rpc_mappings, Some(vec![advertised_mapping()]));
        assert!(
            result
                .observation
                .as_deref()
                .unwrap()
                .starts_with("earlier observation; SMB probe failed: ")
        );
    }
}

#[tokio::test]
async fn smb_candidate_port_alone_does_not_establish_identity() {
    let mut result = measured_open_tcp_port(445);
    collect_smb(&mut result, Duration::from_secs(1), |_, _, _, _| async {
        Err("fixture read timeout".into())
    })
    .await;
    assert_eq!(result.status, PortStatus::Open);
    assert!(result.service.is_none());
    assert!(result.service_information.is_none());
    assert!(result.error.is_none());
    assert_eq!(
        result.observation.as_deref(),
        Some("SMB probe failed: fixture read timeout")
    );
}

#[tokio::test]
async fn smb_collection_skips_other_ports_states_and_scan_modes() {
    for (port, transport, status) in [
        (139, ScanMode::Tcp, PortStatus::Open),
        (80, ScanMode::Tcp, PortStatus::Open),
        (111, ScanMode::Tcp, PortStatus::Open),
        (2049, ScanMode::Tcp, PortStatus::Open),
        (446, ScanMode::Tcp, PortStatus::Open),
        (445, ScanMode::Udp, PortStatus::Open),
        (445, ScanMode::Syn, PortStatus::Open),
        (445, ScanMode::Tcp, PortStatus::Closed),
        (445, ScanMode::Tcp, PortStatus::Filtered),
        (445, ScanMode::Tcp, PortStatus::OpenOrFiltered),
        (445, ScanMode::Tcp, PortStatus::Unknown),
    ] {
        let mut result = measured_open_tcp_port(port);
        result.transport = transport;
        result.status = status;
        collect_smb(&mut result, Duration::from_secs(1), |_, _, _, _| async {
            panic!("SMB exchange must not run for this result")
        })
        .await;
        assert_eq!(result.port, port);
        assert_eq!(result.transport, transport);
        assert_eq!(result.status, status);
        assert_eq!(result.elapsed, Duration::from_millis(17));
        assert!(result.service.is_none());
        assert!(result.service_information.is_none());
        assert!(result.observation.is_none());
    }
}

fn advertised_mapping() -> crate::model::rpc::RpcMapping {
    crate::model::rpc::RpcMapping {
        program: 100000,
        program_version: 2,
        protocol: 6,
        port: 111,
    }
}

fn dump_reply_fixture(xid: u32, mappings: &[crate::model::rpc::RpcMapping]) -> Vec<u8> {
    let mut reply = RPC_REPLY.to_vec();
    reply[..4].copy_from_slice(&xid.to_be_bytes());
    for mapping in mappings {
        reply.extend_from_slice(&[0, 0, 0, 1]);
        for value in [
            mapping.program,
            mapping.program_version,
            mapping.protocol,
            mapping.port,
        ] {
            reply.extend_from_slice(&value.to_be_bytes());
        }
    }
    reply.extend_from_slice(&[0; 4]);
    reply
}

#[tokio::test]
async fn null_identification_then_dump_collection_populates_advertised_mappings() {
    let mut result = measured_open_tcp_port(111);
    let timeout = Duration::from_secs(1);
    collect_rpc(&mut result, timeout, |xid, _, _| async move {
        let mut reply = RPC_REPLY.to_vec();
        reply[..4].copy_from_slice(&xid.to_be_bytes());
        Ok(reply)
    })
    .await;
    let information = result.service_information.clone();
    let before = tokio::time::Instant::now();
    collect_rpc_dump(&mut result, timeout, |xid, deadline, limit| {
        assert!(deadline >= before + timeout);
        assert!(deadline <= tokio::time::Instant::now() + timeout);
        assert_eq!(limit, 4096);
        async move { Ok(dump_reply_fixture(xid, &[advertised_mapping()])) }
    })
    .await;
    assert_eq!(result.rpc_mappings, Some(vec![advertised_mapping()]));
    assert_eq!(result.service.as_deref(), Some("rpcbind"));
    assert_eq!(result.service_information, information);
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert!(result.error.is_none());
    assert!(result.banner.is_none());
}

#[tokio::test]
async fn dump_collection_records_a_successful_empty_list() {
    let mut result = measured_open_tcp_port(111);
    apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
    collect_rpc_dump(
        &mut result,
        Duration::from_secs(1),
        |xid, _, _| async move { Ok(dump_reply_fixture(xid, &[])) },
    )
    .await;
    assert_eq!(result.rpc_mappings, Some(Vec::new()));
    assert_eq!(result.service.as_deref(), Some("rpcbind"));
}

#[tokio::test]
async fn dump_io_and_parse_failures_preserve_successful_null_identification() {
    for failure in ["io", "truncated", "status", "xid"] {
        let mut result = measured_open_tcp_port(111);
        apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
        let information = result.service_information.clone();
        collect_rpc_dump(
            &mut result,
            Duration::from_secs(1),
            |xid, _, _| async move {
                match failure {
                    "io" => Err("fixture DUMP timeout".into()),
                    "truncated" => Ok(Vec::new()),
                    "status" => {
                        let mut reply = dump_reply_fixture(xid, &[]);
                        reply[23] = 1;
                        Ok(reply)
                    }
                    _ => Ok(dump_reply_fixture(xid.wrapping_add(1), &[])),
                }
            },
        )
        .await;
        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.service.as_deref(), Some("rpcbind"));
        assert_eq!(result.service_information, information);
        assert!(result.rpc_mappings.is_none());
        assert!(result.error.is_none());
        assert_eq!(result.elapsed, Duration::from_millis(17));
        let detail = result.observation.as_deref().unwrap();
        assert!(detail.contains("NULL procedure succeeded"));
        assert!(detail.contains("RPC enumeration failed: "));
    }
}

#[tokio::test]
async fn failed_null_identification_prevents_the_dump_exchange() {
    for malformed in [false, true] {
        let mut result = measured_open_tcp_port(111);
        collect_rpc(&mut result, Duration::from_secs(1), |_, _, _| async move {
            if malformed {
                Ok(Vec::new())
            } else {
                Err("fixture NULL failure".into())
            }
        })
        .await;
        let detail = result.observation.clone();
        collect_rpc_dump(&mut result, Duration::from_secs(1), |_, _, _| async {
            panic!("DUMP must not run after failed NULL identification")
        })
        .await;
        assert_eq!(result.observation, detail);
        assert_eq!(result.status, PortStatus::Open);
        assert!(result.service.is_none());
        assert!(result.rpc_mappings.is_none());
    }
}

#[tokio::test]
async fn dump_collection_skips_other_ports_states_and_scan_modes() {
    for (port, transport, status) in [
        (80, ScanMode::Tcp, PortStatus::Open),
        (2049, ScanMode::Tcp, PortStatus::Open),
        (111, ScanMode::Udp, PortStatus::Open),
        (111, ScanMode::Syn, PortStatus::Open),
        (111, ScanMode::Tcp, PortStatus::Closed),
        (111, ScanMode::Tcp, PortStatus::Unknown),
    ] {
        let mut result = measured_open_tcp_port(port);
        result.transport = transport;
        result.status = status;
        result.service = Some("rpcbind".into());
        collect_rpc_dump(&mut result, Duration::from_secs(1), |_, _, _| async {
            panic!("DUMP must not run for this scan result")
        })
        .await;
        assert_eq!(result.status, status);
        assert_eq!(result.transport, transport);
        assert!(result.rpc_mappings.is_none());
    }
}

#[tokio::test]
async fn dump_collection_rejects_lists_above_128_entries_without_storing_partial_data() {
    let mut result = measured_open_tcp_port(111);
    apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
    collect_rpc_dump(
        &mut result,
        Duration::from_secs(1),
        |xid, _, _| async move { Ok(dump_reply_fixture(xid, &vec![advertised_mapping(); 129])) },
    )
    .await;
    assert!(result.rpc_mappings.is_none());
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.service.as_deref(), Some("rpcbind"));
    assert!(
        result
            .observation
            .as_deref()
            .unwrap()
            .contains("maximum of 128 entries")
    );
}

#[test]
fn parsed_dump_mappings_preserve_null_identification_and_measurements() {
    let mut result = measured_open_tcp_port(111);
    apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
    result.banner = Some(b"earlier evidence".to_vec());
    let information = result.service_information.clone();
    let observation = result.observation.clone();
    apply_rpc_dump_result(&mut result, Ok(vec![advertised_mapping()]));
    assert_eq!(result.rpc_mappings, Some(vec![advertised_mapping()]));
    assert_eq!(result.service_information, information);
    assert_eq!(result.observation, observation);
    assert_eq!(result.service.as_deref(), Some("rpcbind"));
    assert_eq!(result.port, 111);
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.transport, ScanMode::Tcp);
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert!(result.error.is_none());
    assert_eq!(
        result.banner.as_deref(),
        Some(b"earlier evidence".as_slice())
    );
}

#[test]
fn dump_failure_preserves_successful_null_results_and_any_existing_mappings() {
    for existing in [None, Some(vec![advertised_mapping()])] {
        let mut result = measured_open_tcp_port(111);
        apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
        let information = result.service_information.clone();
        result.rpc_mappings = existing.clone();
        apply_rpc_dump_result(&mut result, Err("fixture parse failure".into()));
        assert_eq!(result.status, PortStatus::Open);
        assert_eq!(result.service.as_deref(), Some("rpcbind"));
        assert_eq!(result.service_information, information);
        assert_eq!(result.rpc_mappings, existing);
        assert!(result.error.is_none());
        let detail = result.observation.as_deref().unwrap();
        assert!(detail.contains("NULL procedure succeeded"));
        assert!(detail.contains("RPC enumeration failed: fixture parse failure"));
    }
}

#[test]
fn successful_empty_dump_is_distinct_from_no_successful_enumeration() {
    let mut result = measured_open_tcp_port(111);
    assert!(result.rpc_mappings.is_none());
    apply_rpc_probe_result(&mut result, Ok(&RPC_REPLY), 0x12345678);
    apply_rpc_dump_result(&mut result, Ok(Vec::new()));
    assert_eq!(result.rpc_mappings, Some(Vec::new()));
    assert_eq!(result.status, PortStatus::Open);
}

#[test]
fn dump_result_is_ignored_without_successful_tcp_portmapper_identification() {
    for (port, transport, status, service) in [
        (80, ScanMode::Tcp, PortStatus::Open, Some("rpcbind")),
        (111, ScanMode::Udp, PortStatus::Open, Some("rpcbind")),
        (111, ScanMode::Syn, PortStatus::Open, Some("rpcbind")),
        (111, ScanMode::Tcp, PortStatus::Closed, Some("rpcbind")),
        (111, ScanMode::Tcp, PortStatus::Open, None),
        (111, ScanMode::Tcp, PortStatus::Open, Some("http")),
    ] {
        let mut result = measured_open_tcp_port(port);
        result.transport = transport;
        result.status = status;
        result.service = service.map(str::to_string);
        apply_rpc_dump_result(&mut result, Ok(vec![advertised_mapping()]));
        assert!(result.rpc_mappings.is_none());
        assert_eq!(result.service.as_deref(), service);
        assert_eq!(result.status, status);
    }
}

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
