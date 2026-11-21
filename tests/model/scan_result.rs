//! Method/transport invariants for measured results; no probes or external services.

use std::time::Duration;

use super::{PortStatus, ScanMode, ScanResult};

#[test]
fn preserves_scan_method_while_normalizing_transport_for_all_modes() {
    for (method, transport, status) in [
        (ScanMode::Tcp, ScanMode::Tcp, PortStatus::Open),
        (ScanMode::Udp, ScanMode::Udp, PortStatus::OpenOrFiltered),
        (ScanMode::Syn, ScanMode::Tcp, PortStatus::Closed),
        (ScanMode::Ack, ScanMode::Tcp, PortStatus::Unfiltered),
    ] {
        let elapsed = Duration::from_millis(37);
        let result = ScanResult::new(1883, method, status, elapsed);

        assert_eq!(result.method, method);
        assert_eq!(
            result.transport, transport,
            "Wrong transport for {method:?}"
        );
        assert_eq!(result.status, status);
        assert_eq!(result.port, 1883);
        assert_eq!(result.elapsed, elapsed);
    }
}
