//! Validated command-line settings for a scan and optional AI analysis.

use std::time::Duration;

use crate::model::ScanMode;

#[derive(Debug)]
pub struct CliConfig {
    pub target: Vec<String>,
    pub ports: Vec<String>,
    pub open_only: bool,
    pub timeout: Duration,
    pub mode: ScanMode,
    pub use_ai: bool,
    pub concurrency: usize,
}
