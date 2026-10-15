//! Entry point and orchestration of scanning, reporting, and optional AI analysis.

use std::env;
use std::process;

mod ai;
mod cli;
mod model;
mod scan;

const BANNER: &str = r#"
      \       /
   ___ \_____/ ___
  /   \(o   o)/   \
  \___/  ___  \___/
      \ (___) /
     __\_____/__
    / /       \ \
   (_/         \_)

  RRRRR          N   N  M   M    AAA    PPPPP
  R    R         NN  N  MM MM   A   A   P    P
  R    R  -----  N N N  M M M  AAAAAAA  P    P
  RRRRR   -----  N  NN  M   M  A     A  PPPPP
  R   R          N   N  M   M  A     A  P
  R    R         N   N  M   M  A     A  P
"#;

fn main() {
    print_banner();

    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{}", cli::USAGE);
        return;
    }

    let (target, ports, timeout, use_ai) = match cli::parse_cli(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}\n{}", cli::USAGE);
            process::exit(2);
        }
    };

    let port_refs: Vec<&str> = ports.iter().map(String::as_str).collect();
    let results = scan::scan(target.clone(), timeout, &port_refs);
    model::report::print_results(&target, &results);
    if use_ai {
        match ai::config::AiConfig::load()
            .and_then(|config| ai::service::analyze(&config, &results))
        {
            Ok(analysis) => model::report::print_ai_analysis(&analysis),
            Err(error) => eprintln!("\nAI analysis unavailable: {error}"),
        }
    }
}

fn print_banner() {
    println!(
        "{BANNER}\n  v{} - Scan selected TCP ports and report connection outcomes.\n",
        env!("CARGO_PKG_VERSION")
    );
}
