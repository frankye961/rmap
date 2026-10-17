//! CLI parsing and input validation.

use std::net::Ipv4Addr;
use std::time::Duration;

mod config;
pub use config::CliConfig;

use crate::model::{DEFAULT_CONCURRENCY, MAX_CONCURRENCY, ScanMode};

pub const USAGE: &str = "Usage: rmap --target IPV4 [--tcp | --udp] [--ports PORT[,PORT...]] [--timeout-ms MILLISECONDS] [--concurrency N] [--ai]\nDefaults: TCP, all ports from 1 to 65535, timeout 1000 ms, concurrency 256 (1-1024).\nFull-range scans show only open ports; explicit --ports lists show all outcomes.";

pub fn parse_cli(args: &[String]) -> Result<CliConfig, String> {
    let mut target = None;
    let mut ports = None;
    let mut timeout = None;
    let mut use_ai = false;
    let mut concurrency = None;
    let mut mode = None;
    let mut args = args.iter();

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--tcp" | "--udp" => {
                let selected = if flag == "--tcp" {
                    ScanMode::Tcp
                } else {
                    ScanMode::Udp
                };
                if mode.replace(selected).is_some() {
                    return Err("Specify only one scan mode: --tcp or --udp".into());
                }
            }
            "--target" => {
                let value = args.next().ok_or("Missing value for --target")?;
                let address = value
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "--target must be an IPv4 address")?;
                if target.replace(address.to_string()).is_some() {
                    return Err("--target was given more than once".to_string());
                }
            }
            "--ports" => {
                let value = args.next().ok_or("Missing value for --ports")?;
                let mut parsed_ports = Vec::new();
                for item in value.split(',') {
                    let port = item
                        .parse::<u16>()
                        .map_err(|_| format!("Invalid port: {item}"))?;
                    if port == 0 {
                        return Err("Ports must be between 1 and 65535".to_string());
                    }
                    parsed_ports.push(port.to_string());
                }
                if ports.replace(parsed_ports).is_some() {
                    return Err("--ports was given more than once".to_string());
                }
            }
            "--timeout-ms" => {
                let value = args.next().ok_or("Missing value for --timeout-ms")?;
                let milliseconds = value
                    .parse::<u64>()
                    .map_err(|_| "--timeout-ms must be a positive integer")?;
                if milliseconds == 0 {
                    return Err("--timeout-ms must be greater than zero".to_string());
                }
                if timeout
                    .replace(Duration::from_millis(milliseconds))
                    .is_some()
                {
                    return Err("--timeout-ms was given more than once".to_string());
                }
            }
            "--concurrency" => {
                let value = args.next().ok_or("Missing value for --concurrency")?;
                let limit = value
                    .parse::<usize>()
                    .map_err(|_| "--concurrency must be an integer from 1 to 1024")?;
                if !(1..=MAX_CONCURRENCY).contains(&limit) {
                    return Err(format!(
                        "--concurrency must be between 1 and {MAX_CONCURRENCY}"
                    ));
                }
                if concurrency.replace(limit).is_some() {
                    return Err("--concurrency was given more than once".into());
                }
            }
            "--ai" => {
                if use_ai {
                    return Err("--ai was given more than once".into());
                }
                use_ai = true;
            }
            _ => return Err(format!("Unknown option: {flag}")),
        }
    }

    Ok(CliConfig {
        target: target.ok_or("Missing --target")?,
        full_scan: ports.is_none(),
        ports: ports.unwrap_or_else(|| (1..=u16::MAX).map(|port| port.to_string()).collect()),
        timeout: timeout.unwrap_or(Duration::from_millis(1000)),
        mode: mode.unwrap_or(ScanMode::Tcp),
        use_ai,
        concurrency: concurrency.unwrap_or(DEFAULT_CONCURRENCY),
    })
}

#[cfg(test)]
#[path = "../../tests/cli/parsing.rs"]
mod tests;
