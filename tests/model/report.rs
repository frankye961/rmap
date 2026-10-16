use std::time::Duration;

use super::format_result;
use crate::model::{PortStatus, ScanMode, ScanResult};

#[test]
fn reports_transport_uncertainty_and_elapsed_time() {
    let mut result = ScanResult {
        port: 53,
        transport: ScanMode::Udp,
        status: PortStatus::OpenOrFiltered,
        service: None,
        elapsed: Duration::from_millis(1000),
        error: None,
        observation: Some("no response".into()),
    };
    let line = format_result(&result);
    assert!(line.starts_with("53/udp"));
    assert!(line.contains("open|filtered"));
    assert!(line.contains("1000.00 ms"));
    assert!(line.ends_with("no response"));
    result.transport = ScanMode::Tcp;
    result.status = PortStatus::Closed;
    assert!(format_result(&result).starts_with("53/tcp"));
}
