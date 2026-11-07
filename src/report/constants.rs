//! Console layout and truncation bounds, independent of network collection limits.

pub(super) const SCAN_TABLE_WIDTH: usize = 82;
pub(super) const RPC_TABLE_WIDTH: usize = 51;
pub(super) const ERROR_PREVIEW_BYTES: usize = 240;
pub(super) const AI_TITLE_RULE_WIDTH: usize = 55;
pub(super) const AI_REPORT_WIDTH: usize = 76;
pub(super) const MAX_AI_LINES: usize = 60;
pub(super) const MAX_WRAPPED_CHARS: usize = 700;
pub(super) const AI_LINE_PREFIX: &str = "│  ";
pub(super) const TERMINAL_PROGRESS_SECS: u64 = 1;
pub(super) const REDIRECTED_PROGRESS_SECS: u64 = 5;
