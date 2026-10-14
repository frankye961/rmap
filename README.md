# rust-nmap

`rust-nmap` is a Rust learning project for TCP connect port scanning. It attempts a connection to each selected port, keeps the measured outcome in a structured result, and prints a report. The design also separates optional AI interpretation from measured scan results.

## Build and run

Use stable Rust with edition 2024 support. Set the target address, port strings, and timeout in `src/main.rs` before running the executable. Scan only targets you are authorized to test.

```bash
cargo build --release
./target/release/rust-nmap
```

To install the executable:

```bash
cargo install --path . --locked
rust-nmap
```

Cargo's binary installation directory, usually `~/.cargo/bin`, must be on `PATH` to invoke `rust-nmap` by name.

## Scan results

The scanner returns one `ScanResult` for each attempted connection. A result records the port, a `PortStatus`, the connection time, and any connection error. Reporting displays these measurements separately from AI interpretation.

- `open`: a TCP connection succeeded. This does not identify the service or prove a vulnerability.
- `closed`: the connection was refused.
- `filtered`: a tentative label for a connection timeout. One timeout does not prove filtering or that the host is offline.
- `undetermined`: another connection error prevented classification.

After a successful connection, the handler may read up to 512 bytes with a read timeout. Received bytes are observations; a read failure does not change an already successful connection into a closed port.

## Code layout

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | Select the target and ports, then coordinate scanning and reporting |
| `src/model.rs` | Scan result and port status types |
| `src/scanner.rs` | Sequential TCP connection attempts and outcome classification |
| `src/report.rs` | Display measured results |
| `src/config.rs` | Scan configuration and CLI boundary |
| `src/ai/` | Separate AI connection settings and interpretation boundary |

See [architecture](docs/architecture.md) and [AI integration](docs/ai-integration.md) for the intended separation of responsibilities.

## AI configuration

[`.env.example`](.env.example) documents the AI API base URL, optional API key, model identifier, and request timeout. It is a template: the executable does not automatically load `.env` files or make AI requests. Keep credentials out of source control, logs, and reports.
