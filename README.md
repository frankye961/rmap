# rmap (THIS IS A PoC)

`rmap` aims to be a network scanner inspired by Nmap, written in Rust and extended with AI interpretation. Its goal is to find and describe exposed services, then help a user understand what observed service versions might mean, including possible CVE leads. Scan measurements and AI conclusions stay separate so the tool can show what it observed without presenting a model's guess as a fact.

The current implementation scans selected TCP or UDP ports on one IPv4 address, collects limited banners, probes HTTP on port 80, and can ask DeepSeek to interpret the results using a local CVE advisory file. It does not yet offer Nmap's range of scan methods, host discovery, concurrent scanning, broad service fingerprinting, or live CVE database searches. Building it is also a way to learn Rust networking, I/O, timeouts, and error handling.

## How a run works

1. The CLI validates an IPv4 target, a scan mode (`--tcp` or `--udp`), a comma-separated list of ports, and a positive timeout.
2. The common scanner entry point dispatches to the selected transport. UDP sends an empty datagram to each selected port and waits for a response. For each TCP port, the scanner attempts a TCP connection and records its elapsed connection time and outcome in a `ScanResult`.
3. On an open port other than 80, it reads a passive banner. On open port 80, it sends an HTTP `HEAD` probe using a separate connection.
4. The report prints the measured results before any optional AI work.
5. With `--ai`, the program loads AI settings, retrieves matching entries from an optional local advisory file, and sends bounded observations to DeepSeek through Rig. It prints the interpretation in a separate section. AI errors leave the scan report visible.

The startup banner shows a crab, the tool name, and the program version.

## Build and run

Install a stable Rust toolchain with edition 2024 support. From the repository root, run:

```bash
cargo run -- --tcp --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
```

The `--` passes the remaining arguments to `rmap`. This command starts a real scan, so use only a target you are authorized to test. To see the syntax without scanning, run `cargo run -- --help`.

Build and run the release executable directly:

```bash
cargo build --release --locked
./target/release/rmap --tcp --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
```

Or install it as `rmap`:

```bash
cargo install --path . --locked
rmap --tcp --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
```

Cargo installs binaries in a directory usually named `~/.cargo/bin`. That directory must be on `PATH` to run the installed command by name. If `cargo` itself is not found after installing Rust, open a new terminal or load Cargo's shell environment with `. "$HOME/.cargo/env"`. Reinstall after changing the source if you use the installed binary; `cargo build` does not replace it.

Rig is pinned to version 0.42.0, and `Cargo.lock` records the resolved dependencies.

### CLI options

| Option | Meaning |
| --- | --- |
| `--tcp` | Run the TCP connect scanner |
| `--udp` | Send an empty UDP probe to each selected port and wait for a response |
| `--target IPV4` | IPv4 address to scan; hostnames and IPv6 are not accepted |
| `--ports PORT[,PORT...]` | Ports from 1 through 65535, scanned sequentially in the given order |
| `--timeout-ms MILLISECONDS` | Positive timeout for a connection attempt and the later banner read or HTTP probe |
| `--ai` | Request DeepSeek interpretation after the scan report |
| `--help`, `-h` | Show command syntax without scanning |

Exactly one of `--tcp` or `--udp` is required, together with the target, ports, and timeout options. The modes cannot be combined. Invalid input stops the run before any connection attempt.

To scan UDP ports:

```bash
rmap --udp --target 127.0.0.1 --ports 53 --timeout-ms 1000
```

## Understanding scan results

Each report row includes the port, connection state, an optional service label, the elapsed time, and a detail. For TCP, elapsed time measures the initial connection attempt and excludes later banner reads or HTTP probes. For UDP, it measures socket setup, sending, and waiting for a response.

| State | What it means here |
| --- | --- |
| `open` | The TCP connection succeeded or a UDP response was received. This alone does not identify a service or prove a vulnerability. |
| `closed` | The TCP connection was refused, or the OS reported a refused UDP probe. |
| `filtered` | The connection timed out. Filtering is a tentative explanation, not a confirmed fact. |
| `open\|filtered` | No UDP response arrived before the read timeout; an open service may silently ignore the probe. |
| `undetermined` | Another socket or I/O error prevented classification. |

For most open ports, the scanner passively reads up to 512 bytes, stopping at a newline, a read timeout, a closed connection, or the byte limit. The report shows a printable preview of at most 64 bytes. A complete SSH identification line gives the port an `ssh` service label. Other banners remain observations even when the service is unknown.

For open port 80, the scanner makes an HTTP `HEAD` request. A valid HTTP response gives the port an `http` label; the report shows the `Server` header when present. The HTTP probe does not follow redirects or use a configured proxy. It does not display HTTP status codes. A failed probe or banner read does not change a successful TCP connection into a closed result.

Service labels are deliberately limited. A program can run on an unexpected port, and a banner or `Server` header can be missing, misleading, or customized. The scanner does not verify a product version beyond the bytes it observed.

UDP uses a fresh local socket for each port and restricts responses to that target's IP and port. Empty probes are deliberately simple: many UDP services require a valid protocol request and will ignore them. Service identification and protocol-specific UDP probes are not implemented. Closed-port errors depend on what the operating system exposes; silence is never treated as proof of an open or closed port. Response previews escape control bytes and are limited to 64 bytes; datagrams are read into a 1024-byte buffer and may be truncated.

## Optional AI interpretation

Add `--ai` to ask DeepSeek to explain the completed scan:

```bash
cargo run -- --tcp --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000 --ai
```

AI is off by default. When enabled, the application sends at most eight open-port observations and up to five matching local CVE advisory entries to the configured DeepSeek API. The request has bounded text and output, and asks the model to distinguish observations from hypotheses. Target banners and advisory text are treated as untrusted data. The generated interpretation appears separately from measured results and from the retrieved advisory candidates.

CVE matching uses a local UTF-8 tab-separated file supplied by you. Each line has five fields, separated by tabs:

```text
CVE-ID<TAB>product<TAB>exact-version<TAB>https://source-url<TAB>description
```

The reader ignores lines beginning with `#`, accepts a file up to 1 MiB, and selects at most five records whose `product/version` or `product_version` text appears in an open port's observation. For example, an observation containing `Apache/2.4.68` can match an entry for product `Apache` and version `2.4.68`. There is no automatic advisory download, web search, or vector database. If no file or no matching entry is provided, the AI prompt says that no CVE lookup evidence is available and forbids invented CVE IDs.

A matching version string is only a lead. Distribution packages can backport fixes without changing the advertised version, and a banner does not prove the exact software behind a port. Verify any CVE against the authoritative advisory, the installed package, and the vendor's fix information before treating it as applicable.

### AI configuration

Copy [`.env.example`](.env.example) to a local `.env` in the directory where you run `rmap`, or export the same names in your shell. The application reads `.env` only when `--ai` is used. Exported environment variables take precedence over values in the file. `.env` and other local `.env.*` files are Git-ignored; `.env.example` is tracked.

| Variable | Meaning |
| --- | --- |
| `RMAP_AI_BASE_URL` | Optional DeepSeek API base URL; blank uses Rig's default endpoint |
| `RMAP_AI_API_KEY` | Required DeepSeek API key |
| `RMAP_AI_MODEL` | Required model identifier chosen by the user |
| `RMAP_AI_TIMEOUT_MS` | Maximum AI request duration in milliseconds; defaults to `15000` |
| `RMAP_CVE_FILE` | Optional path to your local advisory TSV file |

Existing `RUST_NMAP_*` variables remain accepted as compatibility aliases. Nonempty exported values take precedence over file values; within each source, `RMAP_*` takes precedence over its legacy alias. Your existing local `.env` can keep its previous variable names.

The AI request uses DeepSeek's non-thinking mode to produce a short final answer. The application does not print the API key or provider response body. If configuration, retrieval, or the request fails, it reports the AI error after the measured scan results. Keep credentials out of commits, logs, reports, and shared terminal output.

## Repository layout

```text
src/
├── main.rs             Entry point and orchestration
├── cli/
│   ├── mod.rs          Argument parsing and validation
│   └── config.rs       Reserved for a typed scan configuration
├── scan/
│   ├── mod.rs          Common entry point and transport dispatch
│   ├── tcp.rs          TCP connections, outcomes, and passive banners
│   ├── udp.rs          Sequential UDP probes and outcome classification
│   └── http.rs         HTTP HEAD probe for open port 80
├── model/
│   ├── mod.rs          Scan and AI result types
│   └── report.rs       Terminal rendering of results and interpretation
└── ai/
    ├── mod.rs          AI modules
    ├── config.rs       DeepSeek settings and local .env loading
    ├── retrieval.rs    Local CVE advisory matching
    └── service.rs      Bounded prompt and Rig request

tests/
├── cli/                Scan mode and argument validation tests
├── scan/               TCP, UDP classification, and HTTP unit tests
├── model/              Report formatting tests
└── ai/                 Configuration, retrieval, and service unit tests
```

The tests are in separate files under `tests/`, but each source module includes its tests only in a test build. This keeps private helper functions private while making the test files easy to find. See [architecture](docs/architecture.md) and [AI integration](docs/ai-integration.md) for more detail.

## Local checks

The following commands format, test, lint, and build without making a live scan or DeepSeek request:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo build --release --locked
```
