use std::time::Duration;

use super::{collect_banner, identify_service};
use crate::model::{PortStatus, ScanMode, ScanResult};

#[test]
fn extracts_openssh_software_version_and_distribution_comments() {
    let info = identify_service(b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n").unwrap();
    assert_eq!(info.service.as_deref(), Some("ssh"));
    assert_eq!(info.product.as_deref(), Some("OpenSSH"));
    assert_eq!(info.version.as_deref(), Some("10.0p2"));
    assert_eq!(info.observation.as_deref(), Some("Debian-7+deb13u4"));
}

#[test]
fn supports_compatibility_prefix_and_missing_comments() {
    let info = identify_service(b"SSH-1.99-OpenSSH_8.9p1\r\n").unwrap();
    assert_eq!(info.version.as_deref(), Some("8.9p1"));
    assert!(info.observation.is_none());
}

#[test]
fn does_not_guess_unknown_ssh_software_or_incomplete_versions() {
    for banner in [
        b"SSH-2.0-OtherServer\r\n".as_slice(),
        b"SSH-2.0-OpenSSH_\r\n",
    ] {
        let info = identify_service(banner).unwrap();
        assert_eq!(info.service.as_deref(), Some("ssh"));
        assert!(info.product.is_none());
        assert!(info.version.is_none());
    }
    assert!(identify_service(b"SSH-2.0-\r\n").is_none());
    assert!(identify_service(b"SSH-2.0-OpenSSH_10.0p2").is_none());
    assert!(identify_service(b"SSH-2.0-OpenSSH_10.0p2\n").is_none());
    assert!(identify_service(b"SSH-2.0-OpenSSH_10.0p2\x00\r\n").is_none());
    assert!(identify_service(b"unrecognized data\r\n").is_none());
}

#[test]
fn parses_identification_line_without_decoding_binary_following_it() {
    let mut banner = b"Notice\r\nSSH-2.0-OpenSSH_10.0p2\r\n".to_vec();
    banner.extend_from_slice(&[0xff, 0x80]);
    assert_eq!(
        identify_service(&banner).unwrap().version.as_deref(),
        Some("10.0p2")
    );
}

#[test]
fn identifies_nonstandard_port_without_changing_scan_measurements() {
    let bytes = b"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n".to_vec();
    let mut result = ScanResult {
        port: 2222,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::ZERO,
        error: None,
        observation: Some("peer closed connection".into()),
        banner: Some(bytes.clone()),
        service_information: None,
    };
    collect_banner(&mut result);
    assert_eq!(result.service.as_deref(), Some("ssh"));
    assert_eq!(
        result
            .service_information
            .as_ref()
            .unwrap()
            .version
            .as_deref(),
        Some("10.0p2")
    );
    assert_eq!(result.banner.as_deref(), Some(bytes.as_slice()));
    assert_eq!(
        result.observation.as_deref(),
        Some("peer closed connection")
    );
    result.transport = ScanMode::Udp;
    result.service_information = None;
    collect_banner(&mut result);
    assert!(result.service_information.is_none());
}
