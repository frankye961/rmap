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
            None => identify_ftp(banner),
        },
    }
}

fn identify_ssh(banner: &[u8]) -> Option<ServiceInformation> {
    complete_lines(banner)
        .filter(|line| {
            line.len() + 2 <= 255 && line.iter().all(|byte| (0x20..=0x7e).contains(byte))
        })
        .filter_map(|line| from_utf8(line).ok())
        .find_map(parse_ssh_line)
}

fn parse_ssh_line(text: &str) -> Option<ServiceInformation> {
    let software_and_comments = text
        .strip_prefix("SSH-2.0-")
        .or_else(|| text.strip_prefix("SSH-1.99-"))?;
    let (software, comments) = software_and_comments
        .split_once(' ')
        .map_or((software_and_comments, None), |(software, comments)| {
            (software, Some(comments))
        });
    if software.is_empty() {
        return None;
    }
    // Unknown SSH implementations retain a protocol label without guessed versions.
    let version = software
        .strip_prefix("OpenSSH_")
        .filter(|version| starts_with_digit(version));
    Some(map_tcp_service(
        "ssh",
        version.map(|_| "OpenSSH"),
        version,
        comments,
    ))
}

fn identify_http(banner: &[u8]) -> Option<ServiceInformation> {
    complete_lines(banner)
        .any(|line| line.starts_with(b"HTTP/"))
        .then(|| map_tcp_service("http", None, None, None))
}

fn identify_ftp(banner: &[u8]) -> Option<ServiceInformation> {
    complete_lines(banner)
        .filter_map(|line| from_utf8(line).ok())
        .find_map(|text| parse_vsftpd_line(text).or_else(|| parse_filezilla_line(text)))
}

fn parse_vsftpd_line(text: &str) -> Option<ServiceInformation> {
    let version = text.strip_prefix("220 (vsFTPd ")?.strip_suffix(')')?;
    if !version
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    Some(map_tcp_service("ftp", Some("vsFTPd"), Some(version), None))
}

fn parse_filezilla_line(text: &str) -> Option<ServiceInformation> {
    let rest = text.strip_prefix("220-FileZilla Server")?;
    if !rest.is_empty() && !rest.starts_with(' ') {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("version ").unwrap_or(rest);
    let version = rest.split_whitespace().next().filter(|version| {
        starts_with_digit(version)
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    });
    Some(map_tcp_service(
        "ftp",
        Some("FileZilla Server"),
        version,
        None,
    ))
}

#[cfg(test)]
#[path = "../../tests/scan/identify.rs"]
mod tests;
