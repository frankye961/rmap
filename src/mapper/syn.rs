//! Map SYN measurements into the common scan result model.

use std::net::SocketAddr;
use std::time::Duration;

use crate::model::{PortStatus, ScanMode, ScanResult};

/// Build a TCP result from measured state, elapsed time, and separate diagnostic data.
/// Raw packet bytes are not application banners. Console presentation belongs to report/measured.rs.
pub fn map_syn_result(
    _target: SocketAddr,
    _status: PortStatus,
    _elapsed: Duration,
    _error: Option<String>,
    _observation: Option<String>,
) -> ScanResult {
    let mut result = ScanResult::new(_target.port(), ScanMode::Tcp, _status, _elapsed);
    result.error = _error;
    result.observation = _observation;
    result
}
