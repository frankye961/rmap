//! Presentation of measured results; AI interpretation remains future work.

use crate::model::{PortStatus, ScanResult};

pub fn print_results(target: &str, results: &[ScanResult]) {
    println!("Scan results for {target}\n");
    println!("{:<9} {:<12} {:>11}  DETAIL", "PORT", "STATE", "CONNECT");
    println!("{}", "-".repeat(72));

    for result in results {
        let status = match result.status {
            PortStatus::Open => "open",
            PortStatus::Closed => "closed",
            PortStatus::Filtered => "filtered",
            PortStatus::Unknown => "undetermined",
        };
        let detail = result
            .error
            .as_deref()
            .or(result.observation.as_deref())
            .unwrap_or("-");
        println!(
            "{:<9} {:<12} {:>8.2} ms  {detail}",
            format!("{}/tcp", result.port),
            status,
            result.elapsed.as_secs_f64() * 1_000.0
        );
    }

    if results
        .iter()
        .any(|result| result.status == PortStatus::Filtered)
    {
        println!("\nfiltered = connection timed out; filtering is unconfirmed.");
    }
}
