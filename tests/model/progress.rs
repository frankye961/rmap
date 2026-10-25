use super::format_progress;
use crate::model::ScanMode;
use std::time::Duration;

#[test]
fn progress_distinguishes_completed_ports_from_total_and_identifies_transport() {
    let line = format_progress(50, 100, 443, ScanMode::Tcp, Duration::from_millis(1250));
    assert!(line.contains("50/100 ports (50.0%)"));
    assert!(line.contains("443/tcp"));
    assert!(line.contains("elapsed 1.2s"));
    assert!(format_progress(0, 0, 53, ScanMode::Udp, Duration::ZERO).contains("100.0%"));
    assert!(format_progress(1, 1, 80, ScanMode::Syn, Duration::ZERO).contains("80/tcp"));
}
