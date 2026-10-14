//! Presentation of measured results; AI interpretation remains future work.

use crate::model::{PortStatus, ScanResult};

pub fn print_results(results: &[ScanResult]) {
    for result in results {
        let status = match result.status {
            PortStatus::Open => "open",
            PortStatus::Closed => "closed",
            PortStatus::Filtered => "filtered (tentative: connection timed out)",
            PortStatus::Unknown => "undetermined",
        };

        println!("{}/tcp {status} ({:?})", result.port, result.elapsed);
        if let Some(error) = &result.error {
            println!("  {error}");
        }
    }
}
