//! Common scan entry point, dispatching to the selected transport.

use std::time::Duration;

use crate::model::{ScanMode, ScanResult};

mod http;
mod tcp;
mod udp;

pub fn scan(
    mode: ScanMode,
    address: String,
    timeout: Duration,
    ports: &[&str],
) -> Result<Vec<ScanResult>, String> {
    match mode {
        ScanMode::Tcp => Ok(tcp::scan(address, timeout, ports)),
        ScanMode::Udp => udp::scan(address, timeout, ports),
    }
}
