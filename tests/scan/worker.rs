use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Barrier, Semaphore};

use super::run;
use crate::model::{PortStatus, ScanMode, ScanResult};

fn target(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn result(target: SocketAddr) -> ScanResult {
    ScanResult {
        port: target.port(),
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: None,
        banner: None,
        service_information: None,
    }
}

#[tokio::test]
async fn probes_overlap_without_exceeding_the_worker_limit() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(3));
    let targets: Vec<_> = (1..=6).map(target).collect();
    let mut completed = Vec::new();
    let results = run(
        &targets,
        3,
        ScanMode::Tcp,
        |target| {
            let active = active.clone();
            let peak = peak.clone();
            let barrier = barrier.clone();
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                barrier.wait().await;
                active.fetch_sub(1, Ordering::SeqCst);
                result(target)
            }
        },
        |count, _| completed.push(count),
    )
    .await
    .unwrap();
    assert_eq!(peak.load(Ordering::SeqCst), 3);
    assert_eq!(results.len(), 6);
    assert_eq!(completed, [1, 2, 3, 4, 5, 6]);
}

#[tokio::test]
async fn reports_completion_immediately_but_returns_requested_order_and_duplicates() {
    let release = Arc::new(Semaphore::new(0));
    let targets = [target(80), target(22), target(80)];
    let mut completion_order = Vec::new();
    let results = run(
        &targets,
        2,
        ScanMode::Tcp,
        |target| {
            let release = release.clone();
            async move {
                if target.port() == 80 {
                    tokio::time::timeout(Duration::from_secs(3), release.acquire())
                        .await
                        .unwrap()
                        .unwrap()
                        .forget();
                }
                result(target)
            }
        },
        |_, result| {
            completion_order.push(result.port);
            if result.port == 22 {
                release.add_permits(2);
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(completion_order[0], 22);
    assert_eq!(
        results.iter().map(|result| result.port).collect::<Vec<_>>(),
        [80, 22, 80]
    );
    assert!(
        results
            .iter()
            .all(|result| result.status == PortStatus::Open)
    );
}

#[tokio::test]
async fn one_worker_is_sequential_and_a_panicking_probe_keeps_other_results() {
    let targets = [target(80), target(22), target(443)];
    let mut order = Vec::new();
    let results = run(
        &targets,
        1,
        ScanMode::Tcp,
        |target| async move {
            if target.port() == 22 {
                panic!("simulated probe failure");
            }
            result(target)
        },
        |_, result| order.push(result.port),
    )
    .await
    .unwrap();
    assert_eq!(order, [80, 22, 443]);
    assert_eq!(results[0].status, PortStatus::Open);
    assert_eq!(results[1].status, PortStatus::Unknown);
    assert!(results[1].error.as_deref().unwrap().contains("failed"));
    assert_eq!(results[2].status, PortStatus::Open);
}

#[tokio::test]
async fn zero_workers_is_rejected_and_empty_inputs_need_no_workers() {
    assert!(
        run(
            &[target(80)],
            0,
            ScanMode::Tcp,
            |_| async { panic!("no probe expected") },
            |_, _| {}
        )
        .await
        .is_err()
    );
    assert!(
        run(
            &[],
            256,
            ScanMode::Tcp,
            |_| async { panic!("no probe expected") },
            |_, _| {}
        )
        .await
        .unwrap()
        .is_empty()
    );
}
