//! CLI parsing and input validation.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

mod config;
pub use config::CliConfig;

use crate::model::{DEFAULT_CONCURRENCY, MAX_CONCURRENCY, ScanMode};

const MAX_TARGETS: usize = 4096;

pub const USAGE: &str = "Usage: rmap --target TARGET[,TARGET...] [--tcp | --udp] [--ports LIST] [--exclude-ports LIST] [--timeout-ms MILLISECONDS] [--concurrency N] [--ai]\nDefaults: TCP, all ports from 1 to 65535, timeout 1000 ms, concurrency 256 (1-1024).\nFull-range scans and --ports lists containing ranges show only open ports; individual-port lists show all outcomes.\nPort lists accept individual ports and inclusive ranges, e.g. 22,80-82,443.\nTargets accept IPv4 addresses and CIDR subnets; at most 4096 unique targets. Targets are scanned once each, in first-occurrence order.\n--exclude-ports requires an earlier --ports list and must leave at least one port.";

pub fn parse_cli(args: &[String]) -> Result<CliConfig, String> {
    let mut target = None;
    let mut ports = None;
    let mut open_only = true;
    let mut exclude_ports_seen = false;
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
                let address = parsing_target_list(value)?;
                if target.replace(address).is_some() {
                    return Err("--target was given more than once".to_string());
                }
            }
            "--ports" => {
                let value = args.next().ok_or("Missing value for --ports")?;
                let parsed_ports = parsing_ports_function(value)?;
                open_only = value.contains('-');
                if ports.replace(parsed_ports).is_some() {
                    return Err("--ports was given more than once".to_string());
                }
            }
            "--exclude-ports" => {
                if exclude_ports_seen {
                    return Err("--exclude-ports was given more than once".to_string());
                }
                exclude_ports_seen = true;
                if ports.is_none() {
                    return Err(
                        "--exclude-ports requires --ports to be specified first".to_string()
                    );
                }
                let value = args
                    .next()
                    .filter(|value| !value.starts_with("--"))
                    .ok_or("Missing value for --exclude-ports")?;
                let excluded_ports = parsing_ports_function(value)?;
                if let Some(ref mut existing_ports) = ports {
                    existing_ports.retain(|p| !excluded_ports.contains(p));
                    if existing_ports.is_empty() {
                        return Err("--exclude-ports leaves no ports to scan".to_string());
                    }
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
        open_only,
        ports: ports.unwrap_or_else(|| (1..=u16::MAX).map(|port| port.to_string()).collect()),
        timeout: timeout.unwrap_or(Duration::from_millis(1000)),
        mode: mode.unwrap_or(ScanMode::Tcp),
        use_ai,
        concurrency: concurrency.unwrap_or(DEFAULT_CONCURRENCY),
    })
}

fn parsing_ports_function(s: &str) -> Result<Vec<String>, String> {
    let mut ports = Vec::new();
    for item in s.split(',') {
        if let Some((start, end)) = item.split_once('-') {
            let start_port = start
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {start}"))?;
            let end_port = end
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {end}"))?;
            if start_port == 0 || end_port == 0 || start_port > end_port {
                return Err(format!("Invalid port range: {item}"));
            }
            for port in start_port..=end_port {
                ports.push(port.to_string());
            }
        } else {
            let port = item
                .parse::<u16>()
                .map_err(|_| format!("Invalid port number: {item}"))?;
            if port == 0 {
                return Err("Ports must be between 1 and 65535".to_string());
            }
            ports.push(port.to_string());
        }
    }
    Ok(ports)
}

fn parsing_target_list(targets: &str) -> Result<Vec<String>, String> {
    let mut valid_targets = Vec::new();
    let mut seen = HashSet::new();
    for target in targets.split(',') {
        let (first, last) = if target.contains('/') {
            let (address, prefix) = parsing_target_for_subnet(target)?;
            let (network, broadcast) = calculate_subnet_boundaries(address, prefix);
            let first = u32::from(network);
            let last = u32::from(broadcast);
            // /31 includes both endpoints; /32 includes its single address.
            if prefix < 31 {
                (first + 1, last - 1)
            } else {
                (first, last)
            }
        } else {
            let address = target
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("Invalid IPv4 address: {target}"))?;
            let address = u32::from(address);
            (address, address)
        };
        // Count in u64 so /0 cannot overflow; reject oversized subnets before expansion.
        let count = u64::from(last) - u64::from(first) + 1;
        if count > MAX_TARGETS as u64 {
            return Err(format!(
                "Target subnet {target} exceeds the limit of {MAX_TARGETS} unique targets"
            ));
        }
        for address in first..=last {
            let address = Ipv4Addr::from(address);
            if seen.insert(address) {
                if valid_targets.len() == MAX_TARGETS {
                    return Err(format!(
                        "Target list exceeds the limit of {MAX_TARGETS} unique targets"
                    ));
                }
                valid_targets.push(address.to_string());
            }
        }
    }
    Ok(valid_targets)
}

fn parsing_target_for_subnet(target: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address_str, prefix) = target
        .split_once('/')
        .ok_or_else(|| format!("Invalid subnet format: {target}"))?;
    let address = address_str
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid IPv4 address: {address_str}"))?;
    let prefix_length = prefix
        .parse::<u8>()
        .map_err(|_| format!("Invalid subnet prefix length: {prefix}"))?;

    if prefix_length > 32 {
        return Err(format!("Invalid subnet prefix length: {prefix_length}"));
    }
    Ok((address, prefix_length))
}

fn calculate_subnet_boundaries(address: Ipv4Addr, prefix_length: u8) -> (Ipv4Addr, Ipv4Addr) {
    if prefix_length > 32 {
        panic!("Invalid subnet prefix length: {prefix_length}");
    }
    let mask = if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    };
    let network = u32::from(address) & mask;
    let broadcast = network | !mask;
    (Ipv4Addr::from(network), Ipv4Addr::from(broadcast))
}

#[cfg(test)]
#[path = "../../tests/cli/parsing.rs"]
mod tests;
