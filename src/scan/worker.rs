//! Bounded asynchronous probes with completion progress and ordered results.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::task::JoinSet;

use crate::model::{PortStatus, ScanMode, ScanResult};

pub(super) async fn run<F>(
    targets: &[SocketAddr],
    concurrency: usize,
    mode: ScanMode,
    probe: impl Fn(SocketAddr) -> F,
    mut on_result: impl FnMut(usize, &ScanResult),
) -> Result<Vec<ScanResult>, String>
where
    F: Future<Output = ScanResult> + Send + 'static,
{
    if concurrency == 0 {
        return Err("Concurrency must be greater than zero".into());
    }
    let mut tasks = JoinSet::new();
    let mut pending = HashMap::new();
    let mut next = 0;
    let mut completed = 0;
    let mut results: Vec<Option<ScanResult>> = (0..targets.len()).map(|_| None).collect();

    loop {
        // Schedule only enough tasks to fill the available slots.
        while tasks.len() < concurrency && next < targets.len() {
            let target = targets[next];
            let started = Instant::now();
            let handle = tasks.spawn(probe(target));
            pending.insert(handle.id(), (next, target, started));
            next += 1;
        }
        let Some(finished) = tasks.join_next_with_id().await else {
            break;
        };
        let id = match &finished {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        let (index, target, started) = pending
            .remove(&id)
            .ok_or("A completed probe had no matching target")?;
        let result = match finished {
            Ok((_, result)) => result,
            Err(_) => failed_probe(target, mode, started),
        };
        completed += 1;
        on_result(completed, &result);
        results[index] = Some(result);
    }
    results
        .into_iter()
        .map(|result| result.ok_or_else(|| "A scan result is missing".into()))
        .collect()
}

fn failed_probe(target: SocketAddr, mode: ScanMode, started: Instant) -> ScanResult {
    ScanResult {
        port: target.port(),
        transport: mode.transport(),
        status: PortStatus::Unknown,
        service: None,
        elapsed: started.elapsed(),
        error: Some("Probe task failed; port state is undetermined".into()),
        observation: None,
        banner: None,
        service_information: None,
    }
}

#[cfg(test)]
#[path = "../../tests/scan/worker.rs"]
mod tests;
