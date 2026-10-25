use super::{limit_from_budget, parse_open_file_limit};
use crate::model::ScanMode;

#[test]
fn reads_the_soft_descriptor_limit_instead_of_the_hard_limit() {
    let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                  Max cpu time              unlimited            unlimited            seconds\n\
                  Max open files            1024                 524288               files\n";
    assert_eq!(parse_open_file_limit(limits), Some(1024));
    assert_eq!(
        parse_open_file_limit("Max open files unlimited unlimited files"),
        Some(usize::MAX)
    );
    assert_eq!(
        parse_open_file_limit("Max open files invalid 1024 files"),
        None
    );
    assert_eq!(parse_open_file_limit("Max open files"), None);
    assert_eq!(parse_open_file_limit(""), None);
}

#[test]
fn keeps_headroom_and_accounts_for_each_modes_socket_usage() {
    assert_eq!(
        limit_from_budget(ScanMode::Tcp, 1024, 1024, 8).unwrap(),
        984
    );
    assert_eq!(
        limit_from_budget(ScanMode::Syn, 1024, 1024, 8).unwrap(),
        492
    );
    assert_eq!(
        limit_from_budget(ScanMode::Udp, 1024, 1024, 8).unwrap(),
        984
    );
    assert_eq!(limit_from_budget(ScanMode::Tcp, 16, 1024, 8).unwrap(), 16);
    assert_eq!(
        limit_from_budget(ScanMode::Tcp, 1024, 524288, 8).unwrap(),
        1024
    );
}

#[test]
fn exhausted_budget_is_an_error_instead_of_underflowing() {
    for mode in [ScanMode::Tcp, ScanMode::Udp, ScanMode::Syn] {
        for (limit, open) in [(32, 8), (8, 32), (40, 8)] {
            let error = limit_from_budget(mode, 1024, limit, open).unwrap_err();
            assert!(error.contains("Not enough file descriptors"));
        }
    }
    assert_eq!(limit_from_budget(ScanMode::Tcp, 1024, 41, 8).unwrap(), 1);
    assert_eq!(limit_from_budget(ScanMode::Udp, 1024, 41, 8).unwrap(), 1);
    assert!(limit_from_budget(ScanMode::Syn, 1024, 41, 8).is_err());
    assert_eq!(limit_from_budget(ScanMode::Syn, 1024, 42, 8).unwrap(), 1);
}

#[tokio::test]
async fn a_reduced_budget_still_schedules_every_port_in_a_full_scan() {
    use std::net::SocketAddr;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use crate::model::{PortStatus, ScanResult};
    use crate::scan::worker;

    let concurrency = limit_from_budget(ScanMode::Tcp, 1024, 56, 8).unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let targets: Vec<_> = (1..=u16::MAX)
        .map(|port| SocketAddr::from(([192, 0, 2, 21], port)))
        .collect();
    let open_ports = [22, 80, 111, 139, 445, 2049, 2121, 8000];
    let mut completed = 0;
    let results = worker::run(
        &targets,
        concurrency,
        ScanMode::Tcp,
        |target| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                assert!(count <= concurrency);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
                ScanResult {
                    port: target.port(),
                    transport: ScanMode::Tcp,
                    status: if open_ports.contains(&target.port()) {
                        PortStatus::Open
                    } else {
                        PortStatus::Closed
                    },
                    service: None,
                    elapsed: Duration::ZERO,
                    error: None,
                    observation: None,
                    banner: None,
                    service_information: None,
                }
            }
        },
        |count, _| completed = count,
    )
    .await
    .unwrap();
    assert_eq!(completed, 65535);
    assert_eq!(peak.load(Ordering::SeqCst), concurrency);
    assert_eq!(results.len(), 65535);
    assert!(
        results
            .iter()
            .zip(&targets)
            .all(|(result, target)| result.port == target.port())
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status == PortStatus::Open)
            .map(|result| result.port)
            .collect::<Vec<_>>(),
        open_ports
    );
}
