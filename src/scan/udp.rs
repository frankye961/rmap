//! Entry point reserved for the future UDP scanner.

use std::time::Duration;

use crate::model::ScanResult;

pub fn scan(
    _address: String,
    _timeout: Duration,
    _ports: &[&str],
) -> Result<Vec<ScanResult>, String> {
    Err("UDP scanning is not implemented yet".into())
}
