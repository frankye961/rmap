//! Scan progress on stderr, separate from the final measured report.

use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use crate::model::{ScanMode, ScanResult};

pub struct ScanProgress {
    total: usize,
    started: Instant,
    last_update: Instant,
    terminal: bool,
}

impl ScanProgress {
    pub fn new(
        target: &str,
        mode: ScanMode,
        total: usize,
        timeout: Duration,
        concurrency: usize,
    ) -> Self {
        eprintln!(
            "Starting {} scan of {target}: {total} ports, {} ms timeout, up to {} concurrent probes.",
            mode.as_str(),
            timeout.as_millis(),
            concurrency.min(total)
        );
        let started = Instant::now();
        Self {
            total,
            started,
            last_update: started,
            terminal: io::stderr().is_terminal(),
        }
    }

    pub fn update(&mut self, completed: usize, result: &ScanResult) {
        let interval = Duration::from_secs(if self.terminal { 1 } else { 5 });
        if completed != self.total && self.last_update.elapsed() < interval {
            return;
        }
        let line = format_progress(
            completed,
            self.total,
            result.port,
            result.transport,
            self.started.elapsed(),
        );
        if self.terminal && completed != self.total {
            eprint!("\r{line}     ");
        } else if self.terminal {
            eprintln!("\r{line}     ");
        } else {
            eprintln!("{line}");
        }
        self.last_update = Instant::now();
    }
}

fn format_progress(
    completed: usize,
    total: usize,
    port: u16,
    mode: ScanMode,
    elapsed: Duration,
) -> String {
    let percent = if total == 0 {
        100.0
    } else {
        completed as f64 / total as f64 * 100.0
    };
    format!(
        "Scanned {completed}/{total} ports ({percent:.1}%); last {port}/{}; elapsed {:.1}s",
        mode.as_str(),
        elapsed.as_secs_f64()
    )
}

#[cfg(test)]
#[path = "../../tests/model/progress.rs"]
mod tests;
