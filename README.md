# rust-nmap

`rust-nmap` is a dependency-free Rust learning project for TCP connect scanning. Given an IPv4 address and a list of TCP ports, it attempts each connection in order, records the measured outcome, and prints a report. The project is designed to add optional AI-assisted interpretation of completed results while keeping those interpretations separate from network measurements.

## Start a scan

Install stable Rust with edition 2024 support. From the repository root, run:

```bash
cargo run -- --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
```

The `--` passes the following arguments to `rust-nmap` rather than Cargo. This command starts a scan immediately. Use only an address you are authorized to test. Run `cargo run -- --help` to see the command syntax without scanning.

At startup, the executable displays a crab, its name in large letters, its version, and a one-line description.

If your shell says `cargo: command not found` after installing Rust, load Cargo's shell environment or open a new terminal:

```bash
. "$HOME/.cargo/env"
```

To build a release executable and run it directly:

```bash
cargo build --release
./target/release/rust-nmap --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
```

To install the executable named `rust-nmap`:

```bash
cargo install --path . --locked
rust-nmap --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
```

Cargo's binary installation directory, usually `~/.cargo/bin`, must be on `PATH` to invoke the installed command by name.

## Command input

| Option | Meaning |
| --- | --- |
| `--target IPV4` | IPv4 address to scan |
| `--ports PORT[,PORT...]` | Comma-separated TCP ports in the range 1–65535 |
| `--timeout-ms MILLISECONDS` | Positive timeout for each connection attempt and, after a successful connection, its read |
| `--help` or `-h` | Show the command syntax |

All three scan options are required. Invalid or missing values produce an error before any connection attempt. Ports are scanned sequentially in the order provided. The executable does not accept hostnames, IPv6 addresses, or an `--ai` option.

## Results and interpretation

Each attempted connection produces a `ScanResult` with the port, a `PortStatus`, elapsed connection time, any connection error, and any read observation. The report prints one row per port with the status, connection time in milliseconds, and detail. The displayed status means:

- **open:** the TCP connection succeeded. It does not identify the service or prove a vulnerability.
- **closed:** the connection was refused.
- **filtered:** a tentative label for a connection timeout. One timeout does not prove filtering or that the host is offline.
- **undetermined:** another connection error prevented classification.

After a successful connection, the scanner reads up to 512 bytes with a read timeout. The report shows a printable, escaped preview of at most 64 received bytes, or a short read note. That read is separate from the connection result. A peer that sends no bytes, closes the connection, or causes a read error may still have accepted the TCP connection. The reported elapsed time measures the connection attempt, not the later read.

## Design

CLI input is validated before scanning. The scanner returns structured measurements; reporting displays them. The intended optional AI service would receive completed results only when explicitly enabled and return a separate interpretation. An AI failure must never discard or hide measured results. AI conclusions should distinguish observations from hypotheses, and any target responses or banners must be treated as untrusted data.

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | Parse CLI input and coordinate scanning and reporting |
| `src/model.rs` | Scan result and port status types |
| `src/scanner.rs` | Sequential TCP connection attempts and outcome classification |
| `src/report.rs` | Display measured results |
| `src/config.rs` | Scan configuration module |
| `src/ai/` | Separate AI settings and service modules |

See [architecture](docs/architecture.md) and [AI integration](docs/ai-integration.md) for the design in more detail.

## AI configuration

[`.env.example`](.env.example) documents the intended provider settings:

| Variable | Meaning |
| --- | --- |
| `RUST_NMAP_AI_BASE_URL` | AI API server address |
| `RUST_NMAP_AI_API_KEY` | Authentication credential when the provider requires one |
| `RUST_NMAP_AI_MODEL` | Chosen model identifier |
| `RUST_NMAP_AI_TIMEOUT_MS` | Maximum AI request duration in milliseconds |

AI is not called by the executable. `.env.example` is a template; `.env` files are not loaded automatically. Keep credentials out of source control, logs, and reports. Scan results should be sent to a configured provider only after the user explicitly requests AI interpretation.
