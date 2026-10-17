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
        banner: None,
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

#[test]
fn matches_space_separated_ftp_banner_without_version_prefix_false_positive() {
    let result = ScanResult {
        port: 21,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: Some("read timed out".into()),
        banner: Some(b"220 (vsFTPd 3.0.5)".to_vec()),
    };
    let text = concat!(
        "CVE-2025-14242\tvsftpd\t3.0.5\thttps://security-tracker.debian.org/tracker/CVE-2025-14242\tDistribution-specific patch; applicability requires verification\n",
        "CVE-2025-12345\tvsftpd\t3.0\thttps://example.test\tFixture version prefix\n",
    );
    let candidates = retrieve_from_text(text, &[result]);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, "CVE-2025-14242");
}
