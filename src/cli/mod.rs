//! CLI parsing and input validation.

use std::net::Ipv4Addr;
use std::time::Duration;

mod config;

use crate::model::ScanMode;

pub const USAGE: &str = "Usage: rmap (--tcp | --udp) --target IPV4 --ports PORT[,PORT...] --timeout-ms MILLISECONDS [--ai]";

pub fn parse_cli(
    args: &[String],
) -> Result<(String, Vec<String>, Duration, ScanMode, bool), String> {
    let mut target = None;
    let mut ports = None;
    let mut timeout = None;
    let mut use_ai = false;
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
                    return Err("Choose exactly one scan mode: --tcp or --udp".into());
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
            "--ai" => {
                if use_ai {
                    return Err("--ai was given more than once".into());
                }
                use_ai = true;
            }
            _ => return Err(format!("Unknown option: {flag}")),
        }
    }

    Ok((
        target.ok_or("Missing --target")?,
        ports.ok_or("Missing --ports")?,
        timeout.ok_or("Missing --timeout-ms")?,
        mode.ok_or("Missing scan mode: choose --tcp or --udp")?,
        use_ai,
    ))
}

#[cfg(test)]
#[path = "../../tests/cli/parsing.rs"]
mod tests;
