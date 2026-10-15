//! Structured scan measurements and separate AI analysis data.

pub mod report;

use std::time::Duration;

#[derive(Debug)]
pub struct ScanResult {
    pub port: u16,
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
    pub product: String,
    pub version: String,
    pub description: String,
    pub source: String,
}
