//! Entry point and orchestration of scanning, reporting, and optional AI analysis.

use std::env;
use std::process;

mod ai;
mod cli;
mod mapper;
mod model;
mod scan;
mod utils;

const BANNER: &str = r#"
      \       /
   ___ \_____/ ___
  /   \(o   o)/   \
  \___/  ___  \___/
      \ (___) /
     __\_____/__
    / /       \ \
   (_/         \_)

  RRRRR   M   M    AAA    PPPPP
  R    R  MM MM   A   A   P    P
  R    R  M M M  AAAAAAA  P    P
  RRRRR   M   M  A     A  PPPPP
  R   R   M   M  A     A  P
  R    R  M   M  A     A  P
"#;

fn main() {
    print_banner();

    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{}", cli::USAGE);
        return;
    }

    let cli::CliConfig {
        target: targets,
        ports,
        open_only,
        timeout,
        mode,
        use_ai,
        concurrency,
    } = match cli::parse_cli(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}\n{}", cli::USAGE);
            process::exit(2);
        }
    };

    let ai_config = if use_ai {
        match ai::config::AiConfig::load() {
            Ok(config) => Some(config),
            Err(error) => {
                eprintln!("AI analysis unavailable: {error}");
                None
            }
        }
    } else {
        None
    };
    let port_refs: Vec<&str> = ports.iter().map(String::as_str).collect();
    for target in targets {
        let mut progress =
            model::progress::ScanProgress::new(&target, mode, ports.len(), timeout, concurrency);
        let results = match scan::scan(
            mode,
            target.clone(),
            timeout,
            &port_refs,
            concurrency,
            |completed, result| progress.update(completed, result),
        ) {
            Ok(results) => results,
            Err(error) => {
                eprintln!("{error}");
                process::exit(1);
            }
        };
        model::report::print_results(&target, &results, open_only);
        if let Some(config) = ai_config.as_ref() {
            eprintln!(
                "Starting AI web research and interpretation for {target} (session timeout: {} ms).",
                config.timeout.as_millis()
            );
            match ai::service::analyze(config, &results) {
                Ok(analysis) => model::report::print_ai_analysis(&analysis),
                Err(error) => eprintln!("\nAI analysis unavailable: {error}"),
            }
        }
    }
}

fn print_banner() {
    println!(
        "{BANNER}\n  v{} - Rust network scanner with optional AI interpretation.\n",
        env!("CARGO_PKG_VERSION")
    );
}
