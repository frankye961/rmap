//! Identify services and extract supported software versions from collected banners.

use std::str::from_utf8;

use crate::mapper::service_information::{apply_service_information, map_tcp_service};
use crate::model::service_information::ServiceInformation;
use crate::model::{PortStatus, ScanMode, ScanResult};
use crate::utils::banner::{complete_lines, starts_with_digit};

pub(super) fn collect_banner(result: &mut ScanResult) {
    if result.transport != ScanMode::Tcp || result.status != PortStatus::Open {
        return;
    }
    if let Some(banner) = result.banner.as_deref()
        && let Some(information) = identify_service(banner)
    {
        apply_service_information(result, information);
    }
}

fn identify_service(banner: &[u8]) -> Option<ServiceInformation> {
    match identify_ssh(banner) {
        Some(information) => Some(information),
        None => match identify_http(banner) {
            Some(information) => Some(information),
            None => match identify_ftp(banner) {
                Some(information) => Some(information),
                None => identify_smtp(banner),
            },
        },
    }
}

fn identify_ssh(banner: &[u8]) -> Option<ServiceInformation> {
    // Parse complete identification lines, independently of subsequent binary data.
    for line in complete_lines(banner) {
        if line.len() + 2 > 255 || !line.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            continue;
        }
        let Ok(text) = from_utf8(line) else {
            continue;
        };
        let Some(software_and_comments) = text
            .strip_prefix("SSH-2.0-")
            .or_else(|| text.strip_prefix("SSH-1.99-"))
        else {
            continue;
        };
        let (software, comments) = software_and_comments
            .split_once(' ')
            .map_or((software_and_comments, None), |(software, comments)| {
                (software, Some(comments))
            });
        if software.is_empty() {
            continue;
        }
        // OpenSSH uses an identifiable product_version convention. Other SSH
        // implementations still get a protocol label without guessed software fields.
        let version = software
            .strip_prefix("OpenSSH_")
            .filter(|version| starts_with_digit(version));
        return Some(map_tcp_service(
            "ssh",
            version.map(|_| "OpenSSH"),
            version,
            comments,
        ));
    }
    None
}

fn identify_http(banner: &[u8]) -> Option<ServiceInformation> {
    complete_lines(banner)
        .any(|line| line.starts_with(b"HTTP/"))
        .then(|| map_tcp_service("http", None, None, None))
}

fn identify_ftp(banner: &[u8]) -> Option<ServiceInformation> {
    for line in complete_lines(banner) {
        let Ok(text) = from_utf8(line) else {
            continue;
        };
        let (product, version) = if let Some(rest) = text.strip_prefix("220 (vsFTPd ") {
            let Some(version) = rest.strip_suffix(')') else {
                continue;
            };
            if !version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            {
                continue;
            }
            ("vsFTPd", Some(version))
        } else if let Some(rest) = text.strip_prefix("220-FileZilla Server") {
            if !rest.is_empty() && !rest.starts_with(' ') {
                continue;
            }
            let rest = rest.trim_start();
            let rest = rest.strip_prefix("version ").unwrap_or(rest);
            let version = rest.split_whitespace().next().filter(|version| {
                starts_with_digit(version)
                    && version.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            });
            ("FileZilla Server", version)
        } else {
            continue;
        };
        return Some(map_tcp_service("ftp", Some(product), version, None));
    }
    None
}

fn identify_smtp(banner: &[u8]) -> Option<ServiceInformation> {
    for line in complete_lines(banner) {
        let Ok(text) = from_utf8(line) else {
            continue;
        };
        if !text
            .split_whitespace()
            .any(|word| word == "SMTP" || word == "ESMTP")
        {
            continue;
        }

        if !text.starts_with("220 ") && !text.starts_with("220-") {
            continue;
        }

        let rest = text[4..].trim_start();
        let mut words = rest.split_whitespace();
        let product = words.find(|word| *word == "Postfix" || *word == "Exim");
        let version = match product {
            Some(_) => words.next().filter(|version| {
                starts_with_digit(version)
                    && version.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            }),
            None => None,
        };
        return Some(map_tcp_service("smtp", product, version, None));
    }
    None
}

#[cfg(test)]
#[path = "../../tests/scan/identify.rs"]
mod tests;
