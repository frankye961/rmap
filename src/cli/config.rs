//! Validated command-line settings for a scan and optional AI analysis.

use std::time::Duration;

use crate::model::ScanMode;

#[derive(Debug)]
pub struct CliConfig {
    pub target: String,
    pub ports: Vec<String>,
    pub full_scan: bool,
    pub timeout: Duration,
    pub mode: ScanMode,
    pub use_ai: bool,
    pub concurrency: usize,
}
