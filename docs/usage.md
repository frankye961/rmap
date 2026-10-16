# Running rmap

Build with stable Rust supporting edition 2024:

```bash
cargo build --release --locked
./target/release/rmap --help
```

To install the command:

```bash
cargo install --path . --locked
rmap --help
```

Cargo's installation directory, usually `~/.cargo/bin`, must be on `PATH`. Reinstall after source changes when invoking the installed `rmap`; building the project alone does not update that executable.

## Select TCP or UDP

Exactly one of `--tcp` and `--udp` is required. Provide a numeric IPv4 target, comma-separated ports from 1 through 65535, and a positive timeout in milliseconds. Hostnames and IPv6 are not accepted. Ports are scanned sequentially in the supplied order.

The following examples use a documentation address. Replace it with a target you are authorized to scan.

```bash
rmap --tcp --target 192.0.2.21 --ports 80,22,21,8080,443,111,139,445,2409,8000 --timeout-ms 1000
rmap --udp --target 192.0.2.21 --ports 53,123,161 --timeout-ms 1000
```

TCP connects and then collects a passive banner, or sends an HTTP `HEAD` probe on open port 80. UDP sends an empty datagram; protocol-specific UDP requests and service identification are not implemented. A UDP timeout is reported as `open|filtered` because a listening service may ignore that datagram.

`--timeout-ms` governs individual network operations, not the whole scan. TCP connection time excludes later banner collection. UDP elapsed time includes socket setup and the send/receive attempt. OS scheduling can make measured waits slightly longer than the requested timeout.

## Enable public CVE and exploit research

Create `.env` in the directory from which you run rmap using [`.env.example`](../.env.example) as a template. Configure the existing DeepSeek key, model and optional endpoint, then add the separate Brave Search key:

```dotenv
RMAP_AI_API_KEY=your_deepseek_api_key
RMAP_AI_MODEL=your_chosen_model_identifier
RMAP_SEARCH_API_KEY=your_brave_search_api_key
RMAP_AI_TIMEOUT_MS=60000
```

The values above are placeholders. Keys are separate credentials for separate HTTP services. The prompt describes the research task; the search tool supplies internet access. Never put credentials in the prompt, source code, reports, or commits.

```bash
rmap --tcp --target 192.0.2.21 --ports 80,22,21,8080,443,111,139,445,2409,8000 --timeout-ms 1000 --ai
```

The measured report prints before any AI work. DeepSeek can identify product/version text in observations, search for CVEs and affected versions, and look for public Exploit-DB references. The report displays its interpretation, actual retrieved source links, and research notices separately. Search snippets and model judgments are not confirmation of vulnerability or exploit applicability. The program does not download or execute exploit code.

Research is bounded to eight observed outcomes, six search calls, four results per search, and eight model calls. Open ports receive priority in the observation limit. A scan of more ports can therefore display measurements that do not reach the AI prompt. The total AI timeout includes tool and model calls; increase an existing 15000 ms setting when needed for research.

See the [README's recorded TCP run](../README.md#example-tcp-scan-with-ai-research). Its full console output is under the expandable “Recorded console output” section. The example is recorded model output and may contain incorrect or incomplete conclusions.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `rmap: command not found` | Install with Cargo and add its binary directory to `PATH` |
| Old behavior after rebuilding | Reinstall, or run `./target/release/rmap` directly |
| Search key reported missing | Use the exact name `RMAP_SEARCH_API_KEY`, save the file as `.env`, and launch from the directory containing it |
| Only a DeepSeek key is configured | Add the separate Brave Search key for public web research |
| Key exists in `.env.example` only | Copy the template to `.env`; the application does not read `.env.example` |
| Shell-style `export KEY=value` inside `.env` | Use plain `KEY=value`; the current file parser does not recognize `export` prefixes |
| Unexpected settings | Nonempty exported environment variables take precedence over file settings; legacy aliases are also accepted |
| Web search HTTP failure | Check the search key, provider plan, connectivity and rate limits; the DeepSeek key cannot authenticate Brave requests |
| AI research timeout | Increase `RMAP_AI_TIMEOUT_MS`; measured scan results remain available |
| No CVEs or exploit references returned | Check research notes and source coverage; missing evidence does not prove a service is unaffected |

Use the application's `WEB RESEARCH` notes to check tool activity and configuration independently of the generated interpretation. Do not share keys when reporting configuration problems.

## Local validation

```bash
cargo fmt --check
cargo check --locked --offline
cargo test --locked --offline
cargo clippy --locked --offline -- -D warnings
```

Offline checks require dependencies to be available in the local Cargo cache. These checks do not need a running target or provider credentials.
