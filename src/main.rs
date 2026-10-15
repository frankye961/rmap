//! CLI input and orchestration of scanning and reporting.

use std::env;
use std::net::Ipv4Addr;
use std::process;
use std::time::Duration;

mod ai;
mod config;
mod model;
mod report;
mod scanner;

const USAGE: &str =
    "Usage: rust-nmap --target IPV4 --ports PORT[,PORT...] --timeout-ms MILLISECONDS";
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
        println!("{USAGE}");
        return;
    }

    let (target, ports, timeout) = match parse_cli(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            process::exit(2);
        }
    };

    let port_refs: Vec<&str> = ports.iter().map(String::as_str).collect();
    let results = scanner::scan(target.clone(), timeout, &port_refs);
    report::print_results(&target, &results);
}

fn print_banner() {
    println!(
        "{BANNER}\n  v{} - Scan selected TCP ports and report connection outcomes.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn parse_cli(args: &[String]) -> Result<(String, Vec<String>, Duration), String> {
    let mut target = None;
    let mut ports = None;
    let mut timeout = None;
    let mut args = args.iter();

    while let Some(flag) = args.next() {
        match flag.as_str() {
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
            _ => return Err(format!("Unknown option: {flag}")),
        }
    }

    Ok((
        target.ok_or("Missing --target")?,
        ports.ok_or("Missing --ports")?,
        timeout.ok_or("Missing --timeout-ms")?,
    ))
}
