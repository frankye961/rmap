# rmap (ALPHA version)

Current version: **0.5.6**.

rmap is my research project in networking and cybersecurity. It began as a way
to learn Rust and network programming and has grown into a network scanner
inspired by Nmap, with optional AI-assisted interpretation. I use it to explore
how connectivity and service observations are collected, validated, and explained,
including where the evidence is incomplete or uncertain.

Measured results stay separate from AI conclusions. An open port, a self-reported
banner, or a possible CVE match supports a specific observation; each has limits
that matter when drawing security conclusions. Reproducible lab experiments and
explicit uncertainty are central to the project's research direction.

The longer-term assessment direction includes observations from different source
positions, explicit segmentation policies, and comparisons before and after
remediation. Those assessment features are planned; the current application
provides the scanning and service-identification foundation. See
[research goals and experiment guidance](docs/research.md).

## Contents

- [Capabilities](#capabilities)
- [Build and install](#build-and-install)
- [Quick usage](#quick-usage)
- [Optional AI research](#optional-ai-research)
- [Documentation](#documentation)
- [Development](#development)

## Capabilities

| Area | Current behavior |
| --- | --- |
| Scanning | TCP connect, UDP empty-datagram probes, Linux raw-socket TCP SYN |
| Target selection | IPv4 lists and CIDR, first-occurrence deduplication, up to 4,096 unique hosts |
| Scheduling | Bounded Tokio concurrency with descriptor budgeting; hosts run sequentially |
| Passive identification | SSH, supported FTP/SMTP greetings, and HTTP response prefixes |
| Active identification | HTTP/HTTPS HEAD, portmapper NULL/DUMP, NFSv3 NULL, SMB2 NEGOTIATE |
| Evidence | Measured states, timings, raw passive banners, read/probe diagnostics, structured service information |
| AI research | Optional DeepSeek interpretation with Brave web evidence and optional local advisories |

Release **0.5.6** reorganizes modules, splits large functions, centralizes
shared constants, and separates detailed documentation into focused guides.
Scanning behavior is preserved. SMB2 identification, introduced in **0.5.5**,
retains established open-port measurements when probes fail. A negotiated
protocol revision is kept separate from an unknown software version or OS.

Open ports and advertised banners do not prove vulnerability. UDP silence and
TCP timeouts retain uncertainty. RPC registrations are advertised endpoints,
not additional measured open ports. See [result semantics](docs/results.md).

Host discovery, OS fingerprinting, broader protocol identification, and the
planned multi-position policy assessments remain future work. Offline tests
cover protocol handling; live interoperability and performance still need
controlled-lab validation.

## Build and install

Use stable Rust with edition 2024 support. From the repository root:

```bash
cargo build --release --locked
./target/release/rmap --help
cargo install --path . --locked
rmap --help
```

Cargo's binary directory, normally `~/.cargo/bin`, must be on `PATH` to invoke
`rmap`. Reinstall after source changes; building alone does not replace the
installed executable. If Cargo itself is missing from your shell, open a new
terminal or run `. "$HOME/.cargo/env"`.

## Quick usage

For a target you are authorized to test:

```bash
rmap --tcp --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000
rmap --udp --target 127.0.0.1 --ports 53 --timeout-ms 1000
rmap --target 192.0.2.10,192.0.2.0/30 --ports 22,80-82,443
```

For development, use `cargo run --` followed by the same options. Documentation
addresses such as `192.0.2.10` stand in for your own authorized lab targets.

Only `--target` is required. Defaults are TCP connect, ports **1–65535**, a
**1000 ms** timeout, and up to **256** concurrent probes (maximum **1024**,
subject to descriptor budgeting). Full scans and port lists containing ranges
show only confirmed-open rows; individual-port lists show all outcomes.

`--syn` selects TCP SYN discovery and can be combined with `--tcp`, but not
`--udp`. It requires Linux raw-socket privileges (`CAP_NET_RAW`) and does not
collect application banners. See the [usage guide](docs/usage.md) for all flags,
port exclusions, timing, permissions, and troubleshooting.

## Optional AI research

Add `--ai` to request interpretation after measured results. Configure a local
`.env` using [`.env.example`](.env.example), or export the same variables.
`RMAP_AI_API_KEY` and `RMAP_AI_MODEL` configure DeepSeek;
`RMAP_SEARCH_API_KEY` separately enables Brave web research.

The scanner and measured report work independently of AI. Model conclusions and
search snippets are candidates for verification. Credentials must stay out of
source control, reports, and logs. See [AI configuration and data flow](docs/ai-integration.md)
and the [recorded console example](docs/examples.md).

## Documentation

| Guide | Contents |
| --- | --- |
| [Usage](docs/usage.md) | Commands, CLI reference, defaults, permissions, performance, troubleshooting |
| [Results](docs/results.md) | State semantics, banners, service evidence, and uncertainty |
| [Service identification](docs/service-identification.md) | Automatic HTTP/HTTPS, RPC, NFS, and SMB probe behavior |
| [Recorded example](docs/examples.md) | Anonymized scan and historical AI output, preserved with limitations |
| [Architecture](docs/architecture.md) | Scan flow, separation of measurements and interpretation |
| [Project layout](docs/project-layout.md) | Source responsibilities, constants, and test organization |
| [AI integration](docs/ai-integration.md) | Settings, prompts, search bounds, and optional local advisories |
| [Research](docs/research.md) | Research direction and reproducible experiment guidance |
| [Learning guides](docs/README.md#protocol-learning-guides) | SYN, HTTPS, RPC, NFS, and SMB explanations and primary sources |

## Development

Dependencies are recorded in `Cargo.lock`; Rig is pinned to 0.42.0. With the
required dependencies cached, the following checks run offline:

```bash
cargo fmt --all --check
cargo check --offline --locked
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --release --offline --locked
```

Tests use fixtures, fake probes, and in-memory streams. They do not establish
live scan accuracy, and validation does not require network scans or AI calls.
