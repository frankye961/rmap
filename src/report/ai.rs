//! Bounded console presentation of AI interpretation and its sources.

use super::constants::{
    AI_LINE_PREFIX, AI_REPORT_WIDTH, AI_TITLE_RULE_WIDTH, MAX_AI_LINES, MAX_WRAPPED_CHARS,
};
use crate::model::AiAnalysis;

pub fn print_ai_analysis(analysis: &AiAnalysis) {
    println!("\n╭─ AI INTERPRETATION {}", "─".repeat(AI_TITLE_RULE_WIDTH));
    for line in analysis.interpretation.lines().take(MAX_AI_LINES) {
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
    println!("╰{}", "─".repeat(AI_REPORT_WIDTH));
}

fn print_wrapped(text: &str) {
    let clean: String = text
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_WRAPPED_CHARS)
        .collect();
    let mut line = String::from(AI_LINE_PREFIX);
    for word in clean.split_whitespace() {
        if line.chars().count() + word.chars().count() + 1 > AI_REPORT_WIDTH {
            println!("{line}");
            line = String::from(AI_LINE_PREFIX);
        }
        if line.len() > AI_LINE_PREFIX.len() {
            line.push(' ');
        }
        line.push_str(word);
    }
    println!("{line}");
}
