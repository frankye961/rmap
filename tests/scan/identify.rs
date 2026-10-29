use std::time::Duration;

use super::{collect_banner, identify_http_server, identify_service};
use crate::model::service_information::ServiceInformation;
use crate::model::{PortStatus, ScanMode, ScanResult};

fn assert_http_information(
    header: Option<&str>,
    product: Option<&str>,
    version: Option<&str>,
    comments: Option<&str>,
) {
    assert_eq!(
        identify_http_server(header),
        ServiceInformation {
            transport: ScanMode::Tcp,
            service: Some("http".into()),
            product: product.map(str::to_string),
            version: version.map(str::to_string),
            observation: comments.map(str::to_string),
        },
        "unexpected HTTP identification for {header:?}"
    );
}

#[test]
fn missing_or_empty_http_server_header_keeps_http_identification() {
    for header in [None, Some(""), Some("   "), Some("\t\r\n")] {
        assert_http_information(header, None, None, None);
    }
}

#[test]
fn identifies_plain_http_products_and_trims_surrounding_whitespace() {
    for (header, product) in [
        ("Caddy", "Caddy"),
        (" Caddy ", "Caddy"),
        ("\tCaddy\t", "Caddy"),
        ("Apache", "Apache"),
        ("nginx", "nginx"),
    ] {
        assert_http_information(Some(header), Some(product), None, None);
    }
}

#[test]
fn extracts_http_product_and_version_without_comments() {
    for (header, product, version) in [
        ("Apache/2.4.68", "Apache", "2.4.68"),
        (" nginx/1.26.2 ", "nginx", "1.26.2"),
        ("Caddy/2.10.0", "Caddy", "2.10.0"),
    ] {
        assert_http_information(Some(header), Some(product), Some(version), None);
    }
}

#[test]
fn extracts_one_parenthesized_http_comment_with_or_without_a_version() {
    for (header, product, version, comment) in [
        (
            "Apache/2.4.68 (Debian)",
            "Apache",
            Some("2.4.68"),
            Some("Debian"),
        ),
        (
            " Apache/2.4.68   ( Debian Linux ) ",
            "Apache",
            Some("2.4.68"),
            Some("Debian Linux"),
        ),
        (
            "nginx/1.26.2\t(Linux)",
            "nginx",
            Some("1.26.2"),
            Some("Linux"),
        ),
        ("Caddy (example)", "Caddy", None, Some("example")),
        ("Apache/2.4.68 ()", "Apache", Some("2.4.68"), None),
    ] {
        assert_http_information(Some(header), Some(product), version, comment);
    }
}

#[test]
fn unsupported_or_malformed_http_headers_keep_product_unknown() {
    for header in [
        "Apache httpd",
        "Caddy\tserver",
        "Caddy\nserver",
        "Caddy/",
        "/Caddy",
        "/",
        "Apache//2.4.68",
        "Apache/2.4.68/extra",
        "Apache /2.4.68",
        "Apache/ 2.4.68",
        "Apache/2.4.68\tother",
        "Apache\u{a0}httpd",
        "Apache/2.4.68\u{a0}other",
        "Apache/2.4.68 (Debian",
        "Apache/2.4.68 Debian)",
        "Apache/2.4.68 (Debian) extra",
        "Apache/2.4.68 (Debian) (Linux)",
        "Apache/2.4.68 ((Debian))",
        "Apache/2.4.68(Debian)",
        "Apache/2.4.68\n(Debian)",
        "Apache/2.4.68 (De\0bian)",
        "Caddy\0server",
    ] {
        assert_http_information(Some(header), None, None, None);
    }
}

#[test]
fn passive_http_banner_keeps_protocol_without_guessing_a_product() {
    let info = identify_service(b"HTTP/1.1 200 OK\r\n").unwrap();
    assert_eq!(info.transport, ScanMode::Tcp);
    assert_eq!(info.service.as_deref(), Some("http"));
    assert!(info.product.is_none());
    assert!(info.version.is_none());
    assert!(info.observation.is_none());
}

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

#[test]
fn extracts_vsftpd_product_and_version() {
    let info = identify_service(b"220 (vsFTPd 3.0.5)\r\n").unwrap();
    assert_eq!(info.service.as_deref(), Some("ftp"));
    assert_eq!(info.product.as_deref(), Some("vsFTPd"));
    assert_eq!(info.version.as_deref(), Some("3.0.5"));
}

#[test]
fn ftp_does_not_match_generic_greetings_or_malformed_versions() {
    for banner in [
        b"220 mail.example.test ready\r\n".as_slice(),
        b"220 (vsFTPd 3.0.5)",
        b"220 (vsFTPd 3.0.5\r\n",
        b"220 (vsFTPd )\r\n",
        b"220 (vsFTPd 3..5)\r\n",
        b"220 (vsFTPwrong 3.0.5)\r\n",
    ] {
        assert!(identify_service(banner).is_none());
    }
}

#[test]
fn filezilla_keeps_its_own_product_and_optional_version() {
    let info = identify_service(b"220-FileZilla Server version 1.8.2\r\n").unwrap();
    assert_eq!(info.product.as_deref(), Some("FileZilla Server"));
    assert_eq!(info.version.as_deref(), Some("1.8.2"));
    let info = identify_service(b"220-FileZilla Server\r\n").unwrap();
    assert_eq!(info.product.as_deref(), Some("FileZilla Server"));
    assert!(info.version.is_none());
}

#[test]
fn recognizes_smtp_without_guessing_product_or_version() {
    for banner in [
        b"220 mail.example.test ESMTP ready\r\n".as_slice(),
        b"220 mail.example.test SMTP ready\r\n",
        b"220-mail.example.test ESMTP ready\r\n",
        b"220 mail.example.test ESMTP\r\n",
        b"220 mail.example.test ESMTP OtherMail 1.2.3\r\n",
    ] {
        let info = identify_service(banner).unwrap();
        assert_eq!(info.transport, ScanMode::Tcp);
        assert_eq!(info.service.as_deref(), Some("smtp"));
        assert!(info.product.is_none());
        assert!(info.version.is_none());
    }
}

#[test]
fn extracts_smtp_product_and_adjacent_version_after_hostname() {
    for (banner, product, version) in [
        (
            "220 mail.example.test ESMTP Postfix 3.9.0\r\n",
            "Postfix",
            "3.9.0",
        ),
        ("220 mail.example.test ESMTP Exim 4.98\r\n", "Exim", "4.98"),
        (
            "220-mail.example.test SMTP Exim 4.98-1 ready\r\n",
            "Exim",
            "4.98-1",
        ),
        (
            "220 123.example.test ESMTP Postfix 3.9.0 ready\r\n",
            "Postfix",
            "3.9.0",
        ),
    ] {
        let info = identify_service(banner.as_bytes()).unwrap();
        assert_eq!(info.service.as_deref(), Some("smtp"));
        assert_eq!(info.product.as_deref(), Some(product));
        assert_eq!(info.version.as_deref(), Some(version));
    }
}

#[test]
fn smtp_keeps_known_product_when_version_is_missing_or_invalid() {
    for product in ["Postfix", "Exim"] {
        for suffix in ["", " ready", " ready 4.98", " 4.98;", " v4.98"] {
            let banner = format!("220 mail.example.test ESMTP {product}{suffix}\r\n");
            let info = identify_service(banner.as_bytes()).unwrap();
            assert_eq!(info.service.as_deref(), Some("smtp"));
            assert_eq!(info.product.as_deref(), Some(product));
            assert!(info.version.is_none(), "invented a version for {banner:?}");
        }
    }
}

#[test]
fn rejects_missing_smtp_evidence_invalid_reply_codes_and_incomplete_lines() {
    for banner in [
        b"220 mail.example.test ready\r\n".as_slice(),
        b"220 mail.example.test Postfix 3.9.0\r\n",
        b"250 mail.example.test ESMTP Postfix 3.9.0\r\n",
        b"2200 mail.example.test ESMTP Postfix 3.9.0\r\n",
        b"mail.example.test ESMTP Postfix 3.9.0\r\n",
        b"220 mail.example.test NOTSMTP Postfix 3.9.0\r\n",
        b"220 mail.example.test ESMTPwrong Exim 4.98\r\n",
        b"220 mail.example.test ESMTP Postfix 3.9.0",
        b"220 mail.example.test ESMTP Postfix 3.9.0\n",
        b"220 mail.example.test ESMTP Postfix 3.9.0\xff\r\n",
    ] {
        assert!(identify_service(banner).is_none(), "accepted {banner:?}");
    }
}

#[test]
fn smtp_does_not_replace_ftp_identification_for_shared_220_reply_code() {
    for banner in [
        b"220 (vsFTPd 3.0.5)\r\n".as_slice(),
        b"220-FileZilla Server version 1.8.2\r\n",
    ] {
        assert!(super::identify_smtp(banner).is_none());
        assert_eq!(
            identify_service(banner).unwrap().service.as_deref(),
            Some("ftp")
        );
    }
}

#[test]
fn smtp_collection_on_nonstandard_port_preserves_scan_measurements() {
    let bytes = b"220 mail.example.test ESMTP Exim 4.98\r\n".to_vec();
    let mut result = ScanResult {
        port: 2525,
        transport: ScanMode::Tcp,
        status: PortStatus::Open,
        service: None,
        elapsed: Duration::from_millis(17),
        error: None,
        observation: Some("peer closed connection".into()),
        banner: Some(bytes.clone()),
        service_information: None,
    };
    collect_banner(&mut result);
    assert_eq!(result.service.as_deref(), Some("smtp"));
    let info = result.service_information.as_ref().unwrap();
    assert_eq!(info.product.as_deref(), Some("Exim"));
    assert_eq!(info.version.as_deref(), Some("4.98"));
    assert_eq!(result.port, 2525);
    assert_eq!(result.status, PortStatus::Open);
    assert_eq!(result.elapsed, Duration::from_millis(17));
    assert_eq!(result.banner.as_deref(), Some(bytes.as_slice()));
    assert_eq!(
        result.observation.as_deref(),
        Some("peer closed connection")
    );
    assert!(result.error.is_none());
}
