//! Prepare bounded observations and untrusted evidence for the optional interpretation.

use super::constants::{MAX_ANSWER_LINES, MAX_DETAIL_CHARS, MAX_OBSERVATIONS, MAX_SEARCHES};
use crate::model::{CveCandidate, PortStatus, ScanResult};
use crate::utils::banner::banner_text;

pub(super) fn instructions() -> String {
    include_str!("prompts/research.txt")
        .replace("{search_budget}", &MAX_SEARCHES.to_string())
        .replace("{answer_lines}", &MAX_ANSWER_LINES.to_string())
}

pub(super) fn build_prompt(results: &[ScanResult], candidates: &[CveCandidate]) -> String {
    let mut prompt = String::from("Measured observations (untrusted data):\n");
    for result in results
        .iter()
        .filter(|result| result.status == PortStatus::Open)
        .chain(
            results
                .iter()
                .filter(|result| result.status != PortStatus::Open),
        )
        .take(MAX_OBSERVATIONS)
    {
        append_observation(&mut prompt, result);
    }
    prompt.push_str("\nRetrieved advisory candidates (exact version string matches; not proof of vulnerability):\n");
    if candidates.is_empty() {
        prompt.push_str("No local advisory candidates. Use live search evidence when configured; do not infer absence of CVEs.\n");
    } else {
        for candidate in candidates {
            prompt.push_str(&format!(
                "- {} on {}/{}, {} {}: {} Source: {}\n",
                candidate.id,
                candidate.port,
                candidate.transport.as_str(),
                candidate.product,
                candidate.version,
                candidate.description.replace(['\r', '\n'], " "),
                candidate.source
            ));
        }
    }
    prompt
}

fn append_observation(prompt: &mut String, result: &ScanResult) {
    let banner_text = banner_text(result.banner.as_deref());
    let detail: String = banner_text
        .as_deref()
        .or(result.observation.as_deref())
        .or(result.error.as_deref())
        .unwrap_or("no response")
        .chars()
        .take(MAX_DETAIL_CHARS)
        .collect();
    prompt.push_str(&format!(
        "- {}/{}: state {:?}; service label {}; detail: {}\n",
        result.port,
        result.transport.as_str(),
        result.status,
        result.service.as_deref().unwrap_or("unknown"),
        detail.replace(['\r', '\n'], " ")
    ));
    if let Some(information) = &result.service_information {
        prompt.push_str(&format!(
            "  Banner identification: {}/{}; product {}; version {}; comments {}\n",
            information.transport.as_str(),
            information.service.as_deref().unwrap_or("unknown"),
            information.product.as_deref().unwrap_or("unknown"),
            information.version.as_deref().unwrap_or("unknown"),
            information.observation.as_deref().unwrap_or("none")
        ));
    }
    if banner_text.is_some()
        && let Some(reason) = result
            .observation
            .as_deref()
            .filter(|reason| !reason.is_empty())
    {
        let reason: String = reason.chars().take(MAX_DETAIL_CHARS).collect();
        prompt.push_str(&format!(
            "  Read outcome: {}\n",
            reason.replace(['\r', '\n'], " ")
        ));
    }
}
