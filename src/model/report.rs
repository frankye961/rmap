//! Presentation of measured results and separate AI interpretation.

use crate::model::{AiAnalysis, PortStatus, ScanResult};

pub fn print_results(target: &str, results: &[ScanResult]) {
    println!("Scan results for {target}\n");
    println!(
        "{:<9} {:<14} {:<9} {:>11}  DETAIL",
        "PORT", "STATE", "SERVICE", "ELAPSED"
    );
    println!("{}", "-".repeat(82));

    for result in results {
        println!("{}", format_result(result));
    }

    if results
        .iter()
        .any(|result| result.status == PortStatus::Filtered)
    {
        println!("\nfiltered = connection timed out; filtering is unconfirmed.");
    }
    if results
        .iter()
        .any(|result| result.status == PortStatus::OpenOrFiltered)
    {
        println!(
            "\nopen|filtered = no UDP response before timeout; the port may be open or filtered."
        );
    }
}

pub fn print_ai_analysis(analysis: &AiAnalysis) {
    println!("\n╭─ AI INTERPRETATION {}", "─".repeat(55));
    for line in analysis.interpretation.lines().take(60) {
        print_wrapped(line);
    }
    println!("│");
    println!("│  WEB RESEARCH");
    for note in &analysis.research_notes {
        print_wrapped(note);
    }
    for source in &analysis.web_sources {
        print_wrapped(&source.title);
        print_wrapped(&format!("Source: {}", source.url));
        println!("│");
    }
    if !analysis.candidates.is_empty() {
        println!("│  OPTIONAL LOCAL ADVISORY CANDIDATES");
        for candidate in &analysis.candidates {
            print_wrapped(&format!(
                "{}  {}/{}  {} {}",
                candidate.id,
                candidate.port,
                candidate.transport.as_str(),
                candidate.product,
                candidate.version
            ));
            print_wrapped(&candidate.description);
            print_wrapped(&format!("Source: {}", candidate.source));
            println!("│");
        }
    }
    println!("│  Candidate matches require manual verification, including vendor fixes.");
    println!("╰{}", "─".repeat(76));
}

fn print_wrapped(text: &str) {
    let clean: String = text
        .chars()
        .filter(|ch| !ch.is_control())
        .take(700)
        .collect();
    let mut line = String::from("│  ");
    for word in clean.split_whitespace() {
        if line.chars().count() + word.chars().count() + 1 > 76 {
            println!("{line}");
            line = String::from("│  ");
        }
        if line.len() > "│  ".len() {
            line.push(' ');
        }
        line.push_str(word);
    }
    println!("{line}");
}

fn format_result(result: &ScanResult) -> String {
    let status = match result.status {
        PortStatus::Open => "open",
        PortStatus::Closed => "closed",
        PortStatus::Filtered => "filtered",
        PortStatus::OpenOrFiltered => "open|filtered",
        PortStatus::Unknown => "undetermined",
    };
    let detail = result
        .error
        .as_deref()
        .or(result.observation.as_deref())
        .unwrap_or("-");
    format!(
        "{:<9} {:<14} {:<9} {:>8.2} ms  {detail}",
        format!("{}/{}", result.port, result.transport.as_str()),
        status,
        result.service.as_deref().unwrap_or("-"),
        result.elapsed.as_secs_f64() * 1_000.0
    )
}

#[cfg(test)]
#[path = "../../tests/model/report.rs"]
mod tests;
