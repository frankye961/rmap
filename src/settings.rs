//! Shared scan defaults and resource bounds; protocol constants stay with their modules.

pub const DEFAULT_TIMEOUT_MS: u64 = 1000;
pub const DEFAULT_CONCURRENCY: usize = 256;
pub const MAX_CONCURRENCY: usize = 1024;
pub const MAX_TARGETS: usize = 4096;
