use std::time::Duration;

use crate::model::{PortStatus, ScanMode, ScanResult};

use super::retrieve_from_text;

#[test]
fn retrieves_only_observed_exact_version() {
    let results = vec![ScanResult {
        port: 80,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: Some("http".into()),
        elapsed: Duration::ZERO,
        error: None,
        observation: Some("Server: Apache/2.4.68 (Debian)".into()),
    }];
    let corpus = concat!(
        "CVE-2024-12345\tApache\t2.4.68\thttps://example.test/a\tCandidate one\n",
        "CVE-2024-67890\tApache\t2.4.67\thttps://example.test/b\tCandidate two\n",
        "CVE-2024-67891\tApache\t2.4.6\thttps://example.test/c\tPrefix of observed version\n",
        "CVE-2024-67892\tPache\t2.4.68\thttps://example.test/d\tSuffix of observed product",
    );
    let candidates = retrieve_from_text(corpus, &results);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, "CVE-2024-12345");
}
