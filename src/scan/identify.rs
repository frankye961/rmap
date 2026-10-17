//! Identify services and extract supported software versions from collected banners.

use std::str::from_utf8;

use crate::model::service_information::ServiceInformation;
use crate::model::{PortStatus, ScanMode, ScanResult};

pub(super) fn collect_banner(result: &mut ScanResult) {
    if result.transport != ScanMode::Tcp || result.status != PortStatus::Open {
        return;
    }
    if let Some(banner) = result.banner.as_deref()
        && let Some(information) = identify_service(banner)
    {
        result.service = information.service.clone();
        result.service_information = Some(information);
    }
}

fn identify_service(banner: &[u8]) -> Option<ServiceInformation> {
    identify_ssh(banner).or_else(|| identify_http(banner))
}

fn identify_ssh(banner: &[u8]) -> Option<ServiceInformation> {
    for line in banner.split_inclusive(|byte| *byte == b'\n') {
        // Parse complete identification lines, independently of subsequent binary data.
        let Some(line) = line.strip_suffix(b"\r\n") else {
            continue;
        };
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
            .filter(|version| version.as_bytes().first().is_some_and(u8::is_ascii_digit));
        return Some(ServiceInformation {
            transport: ScanMode::Tcp,
            service: Some("ssh".into()),
            observation: comments.filter(|text| !text.is_empty()).map(str::to_string),
            product: version.map(|_| "OpenSSH".into()),
            version: version.map(str::to_string),
        });
    }
    None
}

fn identify_http(banner: &[u8]) -> Option<ServiceInformation> {
    banner
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| line.ends_with(b"\r\n"))
        .any(|line| line.starts_with(b"HTTP/"))
        .then(|| ServiceInformation {
            transport: ScanMode::Tcp,
            service: Some("http".to_string()),
            observation: None,
            product: None,
            version: None,
        })
}

#[cfg(test)]
#[path = "../../tests/scan/identify.rs"]
mod tests;
