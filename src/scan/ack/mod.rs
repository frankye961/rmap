//! ACK header construction and scaffolding for probe I/O and reply classification.
//!
//! This module is not registered with the application or exposed through a CLI flag yet.
//! Header construction is implemented; next complete setup, reply matching and orchestration.
//! The report will also need an `Unfiltered` outcome before ACK scanning is wired.

use std::net::SocketAddr;
use std::time::Duration;

use crate::model::ScanResult;

mod constants;
mod packet;
mod probe;
mod reply;

/// Future per-port entry point. Its error placeholder creates no scan observation.
/// Adapt the completed function to the scanner's result contract when wiring ACK.
pub(super) async fn scan_port(
    _target: SocketAddr,
    _timeout: Duration,
) -> Result<ScanResult, String> {
    Err("ACK scanning is not implemented".into())
}
