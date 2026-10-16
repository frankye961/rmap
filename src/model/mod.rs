//! Structured scan measurements and separate AI analysis data.

pub mod report;

use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Tcp,
    Udp,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug)]
pub struct ScanResult {
    pub port: u16,
    pub transport: ScanMode,
    pub status: PortStatus,
    pub service: Option<String>,
    pub elapsed: Duration,
    pub error: Option<String>,
    pub observation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    /// Tentative label for a connection timeout; filtering is not proven.
    Filtered,
    /// No UDP response; the port may be open or filtered.
    OpenOrFiltered,
    Unknown,
}

/// Interpretation returned by the optional AI step, kept apart from scan measurements.
pub struct AiAnalysis {
    pub interpretation: String,
    pub candidates: Vec<CveCandidate>,
}

/// Advisory matched to a measured service and version in the local corpus.
pub struct CveCandidate {
    pub id: String,
    pub port: u16,
    pub transport: ScanMode,
    pub product: String,
    pub version: String,
    pub description: String,
    pub source: String,
}
