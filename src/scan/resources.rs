//! Leave descriptor headroom when the operating system exposes its current limits.

use crate::model::ScanMode;

const RESERVED_DESCRIPTORS: usize = 32;

pub(super) fn concurrency_limit(mode: ScanMode, requested: usize) -> Result<usize, String> {
    // Linux exposes the enforced soft limit and the descriptors already in use.
    // Inspect after runtime creation so its reactor descriptors are counted too.
    let budget = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|limits| parse_open_file_limit(&limits))
        .zip(std::fs::read_dir("/proc/self/fd").ok());
    match budget {
        Some((limit, descriptors)) => {
            limit_from_budget(mode, requested, limit, descriptors.count())
        }
        // Other platforms may not expose /proc. Probe errors still remain visible.
        None => Ok(requested),
    }
}

fn parse_open_file_limit(limits: &str) -> Option<usize> {
    let value = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))?
        .split_whitespace()
        .next()?;
    if value == "unlimited" {
        Some(usize::MAX)
    } else {
        value.parse().ok()
    }
}

fn limit_from_budget(
    mode: ScanMode,
    requested: usize,
    limit: usize,
    open: usize,
) -> Result<usize, String> {
    // SYN holds a reserved TCP socket plus a raw socket. TCP drops the initial
    // stream before its HTTP request, so TCP and UDP need one socket per probe.
    let per_probe = match mode {
        ScanMode::Syn => 2,
        ScanMode::Tcp | ScanMode::Udp => 1,
    };
    let available = limit
        .saturating_sub(open)
        .saturating_sub(RESERVED_DESCRIPTORS)
        / per_probe;
    if available == 0 {
        return Err(format!(
            "Not enough file descriptors for scanning: soft limit {limit}, {open} already open; reserving {RESERVED_DESCRIPTORS} for other work"
        ));
    }
    Ok(requested.min(available))
}

#[cfg(test)]
#[path = "../../tests/scan/resources.rs"]
mod tests;
