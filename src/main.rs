//! Entry point and future orchestration of scanning and optional interpretation.

mod ai;
mod config;
mod model;
mod report;
mod scanner;

fn main() {
    let results = scanner::scan(
        "192.168.100.1".to_string(),
        std::time::Duration::from_secs(5),
        &["80"],
    );
    report::print_results(&results);
}
