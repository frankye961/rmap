# rust-nmap

A learning project for a Rust TCP connect scanner with optional AI-assisted interpretation of completed scan results.

## Current status

This repository is a dependency-free skeleton. The executable only prints a placeholder message. It does not parse CLI options, scan ports, or contact an AI provider. See [milestone 1](docs/milestone-1.md) for the first implementation steps. Functional AI integration, concurrency, and host discovery are later work; the presence of modules and documentation does not mean these features are implemented.

## Build and run

Use stable Rust with edition 2024 support.

```bash
cargo build --release
./target/release/rust-nmap
```

To install the executable named `rust-nmap`:

```bash
cargo install --path . --locked
rust-nmap
```

Cargo's binary installation directory (usually `~/.cargo/bin`) must be on `PATH` to invoke the installed executable by name. Both ways of running it currently print the placeholder message.

## Planned CLI

These examples show intended future commands. The options are not implemented yet:

```bash
rust-nmap --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000

rust-nmap --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000 --ai
```

AI will be disabled by default and enabled with `--ai`. Only scan targets you are authorized to test.

## Module map

| Module | Planned responsibility |
| --- | --- |
| `main.rs` | Entry point and orchestration |
| `config.rs` | CLI parsing and scan configuration validation |
| `model.rs` | Scan configuration and result types |
| `scanner.rs` | TCP connection attempts and outcome classification |
| `report.rs` | Display measured results and separate AI interpretation |
| `ai/config.rs` | AI connection settings and validation |
| `ai/service.rs` | Request preparation, HTTP calls, response handling, and interpretation |
| `ai/mod.rs` | AI module declarations |

See [architecture](docs/architecture.md) and [AI integration](docs/ai-integration.md) for the intended data flow and boundaries.

## AI configuration template

`.env.example` documents these future environment variables:

| Variable | Meaning |
| --- | --- |
| `RUST_NMAP_AI_BASE_URL` | AI API server address |
| `RUST_NMAP_AI_API_KEY` | Authentication credential, when required by the provider |
| `RUST_NMAP_AI_MODEL` | Chosen model identifier |
| `RUST_NMAP_AI_TIMEOUT_MS` | Maximum duration of an AI request, in milliseconds |

The planned AI configuration reads environment variables when AI is requested. Missing or invalid AI settings matter only with `--ai`; authentication requirements depend on the provider. `.env.example` is a template, and automatic `.env` loading is not implemented. A local `.env` file would require separate loading or environment export before a future run. Keep credentials out of source control, logs, and reports. Local `.env` and `.env.*` files are ignored, while `.env.example` is tracked.
