//! Shared banner operations; protocol-specific interpretation stays in identification.

use std::borrow::Cow;

/// Yield complete CRLF-terminated lines without their line endings.
pub fn complete_lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split_inclusive(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_suffix(b"\r\n"))
}

/// Escape at most `limit` bytes for safe terminal display.
pub fn escape_bytes(data: &[u8], limit: usize) -> String {
    data.iter()
        .take(limit)
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

pub fn starts_with_digit(text: &str) -> bool {
    text.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

/// Decode collected bytes for research while preserving the stored bytes.
pub fn banner_text(data: Option<&[u8]>) -> Option<Cow<'_, str>> {
    data.filter(|bytes| !bytes.is_empty())
        .map(String::from_utf8_lossy)
}
