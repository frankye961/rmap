//! Structured scan measurements and separate AI analysis data.

pub mod progress;
pub mod report;
pub mod service_information;

use self::service_information::ServiceInformation;
use std::time::Duration;

pub const DEFAULT_CONCURRENCY: usize = 256;
pub const MAX_CONCURRENCY: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Tcp,
    Udp,
    Syn,
}

impl ScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Syn => "syn",
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
    pub banner: Option<Vec<u8>>,
    pub service_information: Option<ServiceInformation>,
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
    pub web_sources: Vec<WebSource>,
    pub research_notes: Vec<String>,
}

/// A public search result actually returned during AI research, not an AI-invented link.
#[derive(Clone, Debug, serde::Serialize)]
pub struct WebSource {
    pub title: String,
    pub url: String,
    pub snippet: String,
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
