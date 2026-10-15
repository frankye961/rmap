//! Bounded retrieval from a user supplied, exact-version CVE advisory file.

use std::fs;
use std::path::Path;

use crate::model::{CveCandidate, PortStatus, ScanResult};

const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_CANDIDATES: usize = 5;

pub fn retrieve(path: Option<&Path>, results: &[ScanResult]) -> Result<Vec<CveCandidate>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let size = fs::metadata(path)
        .map_err(|error| format!("Cannot read CVE file: {error}"))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err("CVE file exceeds the 1 MiB limit".into());
    }
    let text =
        fs::read_to_string(path).map_err(|error| format!("Cannot read CVE file: {error}"))?;
    Ok(retrieve_from_text(&text, results))
}

fn retrieve_from_text(text: &str, results: &[ScanResult]) -> Vec<CveCandidate> {
    let mut candidates = Vec::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let mut fields = line.splitn(5, '\t');
        let (Some(id), Some(product), Some(version), Some(source), Some(description)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if !valid_cve_id(id)
            || !source.starts_with("https://")
            || product.is_empty()
            || version.is_empty()
            || product.len() > 64
            || version.len() > 64
            || source.len() > 240
        {
            continue;
        }
        let slash = format!("{product}/{version}").to_ascii_lowercase();
        let underscore = format!("{product}_{version}").to_ascii_lowercase();
        for result in results
            .iter()
            .filter(|result| result.status == PortStatus::Open)
        {
            let observation = result
                .observation
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase();
            if contains_exact_version(&observation, &slash)
                || contains_exact_version(&observation, &underscore)
            {
                if candidates.iter().any(|candidate: &CveCandidate| {
                    candidate.id == id && candidate.port == result.port
                }) {
                    continue;
                }
                candidates.push(CveCandidate {
                    id: id.to_string(),
                    port: result.port,
                    product: product.to_string(),
                    version: version.to_string(),
                    description: description.chars().take(240).collect(),
                    source: source.to_string(),
                });
                if candidates.len() == MAX_CANDIDATES {
                    return candidates;
                }
            }
        }
    }
    candidates
}

fn contains_exact_version(observation: &str, marker: &str) -> bool {
    observation.match_indices(marker).any(|(start, _)| {
        let valid_prefix = observation[..start]
            .chars()
            .next_back()
            .is_none_or(|previous| !previous.is_ascii_alphanumeric());
        valid_prefix
            && observation[start + marker.len()..]
                .chars()
                .next()
                .is_none_or(|next| {
                    !next.is_ascii_alphanumeric() && !matches!(next, '.' | '-' | '_')
                })
    })
}

fn valid_cve_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = rest.split_once('-') else {
        return false;
    };
    id.len() <= 24
        && year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && number.len() >= 4
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
#[path = "../../tests/ai/retrieval.rs"]
mod tests;
