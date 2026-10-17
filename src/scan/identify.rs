use std::str::from_utf8;

fn collect_banner(result: &mut ScanResult) {
    if let Some(banner) = result.banner.as_ref() {
        result.observation = Some(identify_service(banner));
    }
}

fn identify_service(banner: &[u8]) -> Option<String> {
    if !str::from_utf8(banner).is_ok() {
        return None;
    }
    identify_ssh(banner).or_else(|| identify_http(banner))
}

fn identify_ssh(banner: &[u8]) -> Option<String> {
    banner
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| line.ends_with(b"\r\n"))
        .any(|line| line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-"))
        .then(|| "ssh".to_string())
}

fn identify_http(banner: &[u8]) -> Option<String> {
    banner
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| line.ends_with(b"\r\n"))
        .any(|line| line.starts_with(b"HTTP/"))
        .then(|| "http".to_string())
}
