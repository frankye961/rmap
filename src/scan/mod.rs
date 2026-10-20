//! Validate targets and dispatch bounded concurrent TCP or UDP probes.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::model::{MAX_CONCURRENCY, ScanMode, ScanResult};

mod http;
mod identify;
// Learning exercises: unused until packet building is implemented and integrated.
#[allow(dead_code)]
mod syn;
mod tcp;
mod udp;
mod worker;

pub fn scan(
    mode: ScanMode,
    address: String,
    timeout: Duration,
    ports: &[&str],
    concurrency: usize,
    on_result: impl FnMut(usize, &ScanResult),
) -> Result<Vec<ScanResult>, String> {
    if timeout.is_zero() {
        return Err("Scan timeout must be greater than zero".into());
    }
    if !(1..=MAX_CONCURRENCY).contains(&concurrency) {
        return Err(format!(
            "Concurrency must be between 1 and {MAX_CONCURRENCY}"
        ));
    }
    let targets = targets(&address, ports)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Could not initialize scan runtime: {error}"))?;
    runtime.block_on(worker::run(
        &targets,
        concurrency,
        mode,
        move |target| async move {
            match mode {
                ScanMode::Tcp => tcp::scan_port(target, timeout).await,
                ScanMode::Udp => udp::scan_port(target, timeout).await,
            }
        },
        on_result,
    ))
}

fn targets(address: &str, ports: &[&str]) -> Result<Vec<SocketAddr>, String> {
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| "Target must be an IPv4 address")?;
    ports
        .iter()
        .map(|port| {
            let number = port
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {port}"))?;
            if number == 0 {
                return Err("Ports must be between 1 and 65535".into());
            }
            Ok(SocketAddr::from((address, number)))
        })
        .collect()
}
