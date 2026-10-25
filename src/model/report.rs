//! Presentation of measured results and separate AI interpretation.

use crate::model::{AiAnalysis, PortStatus, ScanResult};
use crate::utils::banner::escape_bytes;

pub fn print_results(target: &str, results: &[ScanResult], open_only: bool) {
    write_results(&mut std::io::stdout().lock(), target, results, open_only)
        .expect("Failed to print scan results");
}

fn write_results(
    output: &mut impl std::io::Write,
    target: &str,
    results: &[ScanResult],
    open_only: bool,
) -> std::io::Result<()> {
    writeln!(output, "Scan results for {target}\n")?;
    writeln!(
        output,
        "{:<9} {:<14} {:<9} {:>11}  DETAIL",
        "PORT", "STATE", "SERVICE", "ELAPSED"
    )?;
    writeln!(output, "{}", "-".repeat(82))?;

    let mut displayed = 0;
    for result in results {
        if !open_only || result.status == PortStatus::Open {
            writeln!(output, "{}", format_result(result))?;
            displayed += 1;
        }
    }
    if open_only {
        let undetermined = results
            .iter()
            .filter(|result| result.status == PortStatus::Unknown)
            .count();
        if displayed == 0 && undetermined > 0 {
            writeln!(
                output,
                "No open ports confirmed; {undetermined} of {} probes were undetermined.",
                results.len()
            )?;
        } else if displayed == 0 {
            writeln!(
                output,
                "No open ports found among {} scanned ports.",
                results.len()
            )?;
        } else {
            writeln!(
                output,
                "\nOpen ports shown: {displayed}; ports scanned: {}.",
                results.len()
            )?;
        }
        if undetermined > 0 {
            writeln!(
                output,
                "Undetermined probes: {undetermined}. These are not confirmed closed or filtered ports."
            )?;
            if let Some(error) = results
                .iter()
                .filter(|result| result.status == PortStatus::Unknown)
                .find_map(|result| result.error.as_deref())
            {
                writeln!(
                    output,
                    "Example failure: {}",
                    escape_bytes(error.as_bytes(), 240)
                )?;
            }
        }
    } else {
        if results
            .iter()
            .any(|result| result.status == PortStatus::Filtered)
        {
            writeln!(
                output,
                "\nfiltered = TCP probe timed out; filtering is unconfirmed."
            )?;
        }
        if results
            .iter()
            .any(|result| result.status == PortStatus::OpenOrFiltered)
        {
            writeln!(
                output,
                "\nopen|filtered = no UDP response before timeout; the port may be open or filtered."
            )?;
        }
    }
    Ok(())
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
    let detail = if let Some(error) = &result.error {
        error.clone()
    } else if let Some(data) = result.banner.as_deref().filter(|data| !data.is_empty()) {
        let preview = format_preview(data);
        match result
            .observation
            .as_deref()
            .filter(|reason| !reason.is_empty())
        {
            Some(reason) => format!("{preview} ({reason})"),
            None => preview,
        }
    } else {
        result
            .observation
            .as_deref()
            .filter(|text| !text.is_empty())
            .unwrap_or("-")
            .to_string()
    };
    format!(
        "{:<9} {:<14} {:<9} {:>8.2} ms  {detail}",
        format!("{}/{}", result.port, result.transport.as_str()),
        status,
        result.service.as_deref().unwrap_or("-"),
        result.elapsed.as_secs_f64() * 1_000.0
    )
}

fn format_preview(data: &[u8]) -> String {
    let data = data
        .strip_suffix(b"\r\n")
        .or_else(|| data.strip_suffix(b"\n"))
        .unwrap_or(data);
    let preview_len = data.len().min(64);
    let preview = escape_bytes(data, preview_len);
    if data.len() > preview_len {
        format!("{preview} (preview truncated)")
    } else {
        preview
    }
}

#[cfg(test)]
#[path = "../../tests/model/report.rs"]
mod tests;
