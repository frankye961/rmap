//! Bounded retrieval from a user supplied, exact-version CVE advisory file.

use std::fs;
use std::path::Path;

use crate::model::{CveCandidate, PortStatus, ScanResult};
use crate::utils::banner::banner_text;

const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_CANDIDATES: usize = 5;
const MAX_IDENTITY_BYTES: usize = 64;
const MAX_SOURCE_BYTES: usize = 240;
const MAX_DESCRIPTION_CHARS: usize = 240;
const MAX_CVE_ID_BYTES: usize = 24;
const CVE_YEAR_DIGITS: usize = 4;
const MIN_CVE_NUMBER_DIGITS: usize = 4;

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

struct Advisory<'a> {
    id: &'a str,
    product: &'a str,
    version: &'a str,
    source: &'a str,
    description: &'a str,
}

fn parse_advisory(line: &str) -> Option<Advisory<'_>> {
    let mut fields = line.splitn(5, '\t');
    let advisory = Advisory {
        id: fields.next()?,
        product: fields.next()?,
        version: fields.next()?,
        source: fields.next()?,
        description: fields.next()?,
    };
    if !valid_cve_id(advisory.id)
        || !advisory.source.starts_with("https://")
        || advisory.product.is_empty()
        || advisory.version.is_empty()
        || advisory.product.len() > MAX_IDENTITY_BYTES
        || advisory.version.len() > MAX_IDENTITY_BYTES
        || advisory.source.len() > MAX_SOURCE_BYTES
    {
        return None;
    }
    Some(advisory)
}

fn retrieve_from_text(text: &str, results: &[ScanResult]) -> Vec<CveCandidate> {
    let mut candidates = Vec::new();
    for advisory in text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(parse_advisory)
    {
        let markers = ['/', '_', ' '].map(|separator| {
            format!("{}{separator}{}", advisory.product, advisory.version).to_ascii_lowercase()
        });
        for result in results
            .iter()
            .filter(|result| result.status == PortStatus::Open)
        {
            if !matches_observation(result, &markers)
                || candidates.iter().any(|candidate: &CveCandidate| {
                    candidate.id == advisory.id
                        && candidate.port == result.port
                        && candidate.transport == result.transport
                })
            {
                continue;
            }
            candidates.push(map_candidate(&advisory, result));
            if candidates.len() == MAX_CANDIDATES {
                return candidates;
            }
        }
    }
    candidates
}

fn matches_observation(result: &ScanResult, markers: &[String]) -> bool {
    let banner = banner_text(result.banner.as_deref());
    let observation = banner
        .as_deref()
        .or(result.observation.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    markers
        .iter()
        .any(|marker| contains_exact_version(&observation, marker))
}

fn map_candidate(advisory: &Advisory<'_>, result: &ScanResult) -> CveCandidate {
    CveCandidate {
        id: advisory.id.to_string(),
        port: result.port,
        transport: result.transport,
        product: advisory.product.to_string(),
        version: advisory.version.to_string(),
        description: advisory
            .description
            .chars()
            .take(MAX_DESCRIPTION_CHARS)
            .collect(),
        source: advisory.source.to_string(),
    }
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
    id.len() <= MAX_CVE_ID_BYTES
        && year.len() == CVE_YEAR_DIGITS
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && number.len() >= MIN_CVE_NUMBER_DIGITS
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
#[path = "../../tests/ai/retrieval.rs"]
mod tests;
