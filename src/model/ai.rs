//! Optional interpretation, advisory candidates, and retrieved web evidence.

use super::ScanMode;

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
