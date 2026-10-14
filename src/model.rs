//! Structured results for individual TCP connection attempts.

use std::time::Duration;

#[derive(Debug)]
pub struct ScanResult {
    pub port: u16,
    pub status: PortStatus,
    pub elapsed: Duration,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    /// Tentative label for a connection timeout; filtering is not proven.
    Filtered,
    Unknown,
}
