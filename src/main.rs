//! Entry point and orchestration of scanning, reporting, and optional AI analysis.

use std::env;
use std::process;

mod ai;
mod cli;
mod mapper;
mod model;
mod report;
mod scan;
mod settings;
mod utils;

fn main() {
    report::print_banner();
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{}", cli::usage());
        return;
    }
    let config = cli::parse_cli(&args).unwrap_or_else(|error| {
        eprintln!("{error}\n{}", cli::usage());
        process::exit(2);
    });
    if let Err(error) = run(&config) {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run(config: &cli::CliConfig) -> Result<(), String> {
    let ai_config = load_ai_config(config.use_ai);
    let ports: Vec<&str> = config.ports.iter().map(String::as_str).collect();
    for target in &config.target {
        let mut progress = report::progress::ScanProgress::new(
            target,
            config.mode,
            ports.len(),
            config.timeout,
            config.concurrency,
        );
        let results = scan::scan(
            config.mode,
            target.clone(),
            config.timeout,
            &ports,
            config.concurrency,
            |completed, result| progress.update(completed, result),
        )?;
        report::print_results(target, &results, config.open_only);
        if let Some(ai_config) = ai_config.as_ref() {
            print_interpretation(target, ai_config, &results);
        }
    }
    Ok(())
}

fn load_ai_config(enabled: bool) -> Option<ai::config::AiConfig> {
    if !enabled {
        return None;
    }
    match ai::config::AiConfig::load() {
        Ok(config) => Some(config),
        Err(error) => {
            eprintln!("AI analysis unavailable: {error}");
            None
        }
    }
}

fn print_interpretation(
    target: &str,
    config: &ai::config::AiConfig,
    results: &[model::ScanResult],
) {
    eprintln!(
        "Starting AI web research and interpretation for {target} (session timeout: {} ms).",
        config.timeout.as_millis()
    );
    match ai::service::analyze(config, results) {
        Ok(analysis) => report::print_ai_analysis(&analysis),
        Err(error) => eprintln!("\nAI analysis unavailable: {error}"),
    }
}
