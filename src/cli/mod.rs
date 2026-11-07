//! CLI parsing, with port and target validation separated from option handling.

use std::slice::Iter;
use std::time::Duration;

mod config;
mod help;
mod ports;
mod targets;

use crate::model::ScanMode;
use crate::settings::{DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT_MS, MAX_CONCURRENCY};
pub use config::CliConfig;
pub use help::usage;

#[derive(Default)]
struct Options {
    target: Option<Vec<String>>,
    ports: Option<Vec<String>>,
    open_only: Option<bool>,
    exclude_ports_seen: bool,
    timeout: Option<Duration>,
    use_ai: bool,
    concurrency: Option<usize>,
    mode: Option<ScanMode>,
    use_syn: bool,
}

pub fn parse_cli(args: &[String]) -> Result<CliConfig, String> {
    let mut options = Options::default();
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        options.parse_option(flag, &mut args)?;
    }
    options.finish()
}

impl Options {
    fn parse_option(&mut self, flag: &str, args: &mut Iter<'_, String>) -> Result<(), String> {
        match flag {
            "--tcp" | "--udp" => self.set_mode(flag),
            "--syn" => set_flag(&mut self.use_syn, flag),
            "--ai" => set_flag(&mut self.use_ai, flag),
            "--target" => {
                let targets = targets::parse_targets(next_value(args, flag)?)?;
                set_once(&mut self.target, targets, flag)
            }
            "--ports" => {
                let value = next_value(args, flag)?;
                let ports = ports::parse_ports(value)?;
                self.open_only = Some(value.contains('-'));
                set_once(&mut self.ports, ports, flag)
            }
            "--exclude-ports" => self.exclude_ports(args),
            "--timeout-ms" => {
                let timeout = parse_timeout(next_value(args, flag)?)?;
                set_once(&mut self.timeout, timeout, flag)
            }
            "--concurrency" => {
                let limit = parse_concurrency(next_value(args, flag)?)?;
                set_once(&mut self.concurrency, limit, flag)
            }
            _ => Err(format!("Unknown option: {flag}")),
        }
    }

    fn set_mode(&mut self, flag: &str) -> Result<(), String> {
        let selected = if flag == "--tcp" {
            ScanMode::Tcp
        } else {
            ScanMode::Udp
        };
        if self.mode.replace(selected).is_some() {
            return Err("Specify --tcp or --udp only once; they cannot be combined".into());
        }
        Ok(())
    }

    fn exclude_ports(&mut self, args: &mut Iter<'_, String>) -> Result<(), String> {
        set_flag(&mut self.exclude_ports_seen, "--exclude-ports")?;
        let ports = self
            .ports
            .as_mut()
            .ok_or("--exclude-ports requires --ports to be specified first")?;
        let value = args
            .next()
            .filter(|value| !value.starts_with("--"))
            .ok_or("Missing value for --exclude-ports")?;
        let excluded = ports::parse_ports(value)?;
        ports.retain(|port| !excluded.contains(port));
        if ports.is_empty() {
            return Err("--exclude-ports leaves no ports to scan".into());
        }
        Ok(())
    }

    fn finish(self) -> Result<CliConfig, String> {
        let mode = if self.use_syn {
            if self.mode == Some(ScanMode::Udp) {
                return Err("--syn applies to TCP and cannot be combined with --udp".into());
            }
            ScanMode::Syn
        } else {
            self.mode.unwrap_or(ScanMode::Tcp)
        };
        Ok(CliConfig {
            target: self.target.ok_or("Missing --target")?,
            ports: self
                .ports
                .unwrap_or_else(|| (1..=u16::MAX).map(|port| port.to_string()).collect()),
            open_only: self.open_only.unwrap_or(true),
            timeout: self
                .timeout
                .unwrap_or(Duration::from_millis(DEFAULT_TIMEOUT_MS)),
            mode,
            use_ai: self.use_ai,
            concurrency: self.concurrency.unwrap_or(DEFAULT_CONCURRENCY),
        })
    }
}

fn next_value<'a>(args: &mut Iter<'a, String>, flag: &str) -> Result<&'a str, String> {
    args.next()
        .map(String::as_str)
        .ok_or_else(|| format!("Missing value for {flag}"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{flag} was given more than once"));
    }
    Ok(())
}

fn set_flag(slot: &mut bool, flag: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("{flag} was given more than once"));
    }
    *slot = true;
    Ok(())
}

fn parse_timeout(value: &str) -> Result<Duration, String> {
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| "--timeout-ms must be a positive integer")?;
    if milliseconds == 0 {
        return Err("--timeout-ms must be greater than zero".into());
    }
    Ok(Duration::from_millis(milliseconds))
}

fn parse_concurrency(value: &str) -> Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| format!("--concurrency must be an integer from 1 to {MAX_CONCURRENCY}"))?;
    if !(1..=MAX_CONCURRENCY).contains(&limit) {
        return Err(format!(
            "--concurrency must be between 1 and {MAX_CONCURRENCY}"
        ));
    }
    Ok(limit)
}

#[cfg(test)]
#[path = "../../tests/cli/parsing.rs"]
mod tests;
