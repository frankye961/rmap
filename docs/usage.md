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

## Select TCP connect, TCP SYN, or UDP

Only `--target` is required; it accepts a comma-separated list of numeric IPv4 addresses and CIDR subnets. Omit the mode flags to use TCP connect, or select `--udp` or `--syn` explicitly. `--tcp` and `--udp` cannot be combined or repeated. `--syn` works alone or with `--tcp` in either order; it cannot be repeated or combined with `--udp`. Omit `--timeout-ms` to use 1000 milliseconds, or supply a positive integer to override it. Optionally select comma-separated ports and inclusive ranges from 1 through 65535 with `--ports`, for example `22,80-82,443`. Omitting `--ports` selects all 65535 ports in ascending order. An explicitly empty value or a `--ports` flag without a value is rejected. Hostnames and IPv6 are not accepted. Probes run concurrently, with up to 256 active tasks by default. The final report preserves the supplied port order, regardless of completion order.

### SYN mode

`--syn` (or `--tcp --syn`) uses Linux raw TCP sockets and needs `CAP_NET_RAW`.
Raw-socket availability is checked before ports are scheduled; missing privileges
produce an actionable error. Open-only reports show a count and example error
for undetermined probes instead of silently hiding local failures. It does not run the
TCP connect banner reader or HTTP probe. Validated matching SYN/ACK and RST/ACK
responses become open and closed TCP results. No matching response before the
shared send/receive deadline is tentatively filtered; local I/O failures are
undetermined. Cleanup diagnostics do not erase an open result.

Reset cleanup has at most 100 ms of the remaining probe deadline. Setup time is
included in elapsed measurements but precedes the timeout budget. No ICMP error
interpretation, unanswered-probe retries, or live performance validation is
included. Use a small explicit port list and low concurrency for initial
authorized validation. See [README SYN mode](../README.md#tcp-syn-scanning).

```bash
rmap --target 192.0.2.10,192.0.2.11,192.0.2.10 --ports 22,80-82
```

Targets are deduplicated in first-occurrence order: this scans `192.0.2.10` once and `192.0.2.11` once. Every entry is validated before scanning; empty entries, malformed addresses, and invalid CIDR prefixes are rejected. Hosts are processed sequentially, with concurrent ports and separate progress and reports per host. CIDR expansion selects addresses without first checking whether they are online. Optional AI research runs after each host’s measured report, using only that host’s results and a separate session budget. An AI failure does not stop later hosts; a scan-level failure terminates the run.

CIDR entries use an IPv4 address and a prefix from 0 through 32:

```bash
rmap --target 192.0.2.3/30,192.0.2.10 --ports 22,80,443
```

The subnet is normalized to `192.0.2.0/30`, yielding `192.0.2.1` and `192.0.2.2`, followed by the individual target `192.0.2.10`. Expansion is ascending within each subnet, with duplicates removed across all entries. `/0` through `/30` exclude network and broadcast addresses; `/31` includes both endpoints and `/32` includes one address. The combined list is limited to **4,096 unique targets**, including individual addresses. Subnets exceeding that count are rejected before expansion; combined selections exceeding it are rejected before scanning. `/0` parses successfully but exceeds the limit. All selected addresses are scanned without a separate discovery phase.

To remove selected ports, supply `--exclude-ports` after an explicit `--ports` list:

```bash
rmap --tcp --target 192.0.2.21 --ports 22,80,443 --exclude-ports 22
```

The selected list becomes 80,443; the same exclusion behavior applies to UDP. Remaining ports keep their original order. Without the flag, no ports are excluded. Excluding a port not in the selected list has no effect. The flag may appear only once, requires a valid comma-separated list of ports or inclusive ranges from 1 through 65535, and must leave at least one selected port. A missing value or a following option instead of a value is rejected. Exclusions before `--ports` or without it are rejected, including for default full scans. Both flags accept ranges such as `1-1024`. Range endpoints must be nonzero and fit in `u16`, with start no greater than end. A range with equal endpoints selects one port. Missing endpoints, extra separators, and invalid numbers are rejected. Expansions preserve input order and duplicates.

```bash
rmap --target 192.0.2.21 --ports 22,80-84,443 --exclude-ports 81-83
```

This scans 22,80,84,443. Any `--ports` list containing a range displays only confirmed open ports, including this mixed list and `--ports 1-65535`. All selected ports are still probed.

The minimal command uses TCP, ports 1–65535, and a 1000 ms timeout:

```bash
rmap --target 192.0.2.21
```

Defaults apply when options are omitted. An explicit empty, zero, or missing timeout value is rejected, as is a literal `null` value.

The following examples use a documentation address. Replace it with a target you are authorized to scan.

```bash
rmap --tcp --target 192.0.2.21 --ports 80,22,21,8080,443,111,139,445,2409,8000 --timeout-ms 1000
rmap --udp --target 192.0.2.21 --ports 53,123,161 --timeout-ms 1000
```

To select the entire port range for either transport, leave out `--ports`:

```bash
rmap --tcp --target 192.0.2.21 --timeout-ms 1000
rmap --udp --target 192.0.2.21 --timeout-ms 1000
```

Full-range scans use the same bounded Tokio task scheduler as explicit port lists. Startup output confirms the selected count, timeout, and concurrency limit. Progress is shown on stderr, refreshed about once per second in a terminal or every five seconds when redirected, and again at completion. The final measured table follows the scan. Adding `--ai` runs research after the whole scan; it does not increase the eight-observation limit for AI context.

Use `--concurrency N` to set the maximum active probes from 1 through 1024; the default is 256. Setting it to 1 runs sequentially. The limit covers connection attempts and banner/probe waits. Tasks share a single-thread Tokio runtime with asynchronous sockets, so waiting probes do not need individual OS threads. Only the configured number of tasks is scheduled at once. Missing, repeated, zero, and out-of-range values are rejected before scanning.

```bash
rmap --target 192.0.2.21 --concurrency 256
```

More concurrent probes do not guarantee better performance. Network latency, banner waits, socket limits, and target rate limiting affect speed and observed timeouts. Reduce concurrency when resource errors or excessive timeouts appear.

On Linux, rmap lowers concurrency when necessary to fit the current process's
soft descriptor limit. It counts open descriptors after Tokio starts, leaves 32
for other work, and allows one per TCP/UDP probe or two per SYN probe. A notice
reports the reduced limit; all selected ports are still scheduled. An exhausted
budget stops the scan with an error. If `/proc` cannot be read, the requested
limit is used. This check does not add retries or adapt to network congestion.

If most ports stay silent, estimate full-scan time as
`port count / effective concurrency × timeout`. At 1000 ms, 65,535 ports take
roughly 256 seconds at concurrency 256, or 67 seconds at concurrency 984,
excluding extra overhead and banner waits. This is an estimate, not a deadline;
immediate refusals can be much faster. A one-second full scan is not the expected
baseline when most probes must wait for their timeout.

For a full scan that misses ports observed in a small scan:

1. Check the report's undetermined-probe count and sample error. A local failure
   is not evidence of a closed or filtered port.
2. Run `ulimit -Sn` in the shell used to start rmap to inspect its soft open-file
   limit. Watch for a concurrency-reduction notice.
3. Compare the same explicit ports using lower concurrency, for example:

   ```bash
   rmap --tcp --target 192.0.2.21 --ports 21,22,80,111,139,445,2049,2121,8000 --concurrency 32 --timeout-ms 1000
   ```

4. If timeouts remain, investigate network loss and target rate limiting, then
   consider a longer timeout. Match port selection and scan mode when comparing
   tools. These single-attempt probes do not provide Nmap's adaptive scheduling.

After rebuilding changes, use `./target/release/rmap` directly or reinstall with
`cargo install --path . --locked`; an existing installed binary is not replaced
by `cargo build --release`.

When `--ports` is omitted or its value contains a range, only confirmed `open` ports are printed in the measured table. UDP `open|filtered` rows are hidden. The report gives the number of open ports shown and total scanned, or says no open ports were found. This filters presentation only: all outcomes remain available for progress and bounded AI context. With an explicit list of individual ports, every selected outcome is displayed. A range in exclusions alone does not change this mode.

TCP connects and then collects a passive banner, or sends an HTTP `HEAD` probe on open port 80. UDP sends an empty datagram; protocol-specific UDP requests and service identification are not implemented. A UDP timeout is reported as `open|filtered` because a listening service may ignore that datagram.

Passive banner recognition supports SSH, HTTP, selected FTP greetings, and SMTP greetings. For SMTP, a complete CRLF-terminated `220 ` or `220-` greeting must contain an exact uppercase `SMTP` or `ESMTP` token. The service label becomes `smtp`, even without a known product. Separate `Postfix` and `Exim` tokens supply a product; an immediately following supported version token supplies the version. Unknown fields stay unset. Port numbers do not determine the service label.

For example, `220 mail.example.test ESMTP Exim 4.98` identifies SMTP, Exim, and version 4.98. `220 mail.example.test ESMTP Postfix` identifies SMTP and Postfix without guessing a version. No SMTP commands, TLS negotiation, slash-style version parsing, or complete multiline greeting collection are implemented.

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

AI settings are validated before scanning so configuration errors are visible early. Such errors disable only the AI phase. The measured report prints before any model or web research requests; a separate status message announces the start of the AI phase and its session timeout. DeepSeek can identify product/version text in observations, search for CVEs and affected versions, and look for public Exploit-DB references. The report displays its interpretation, actual retrieved source links, and research notices separately. Search snippets and model judgments are not confirmation of vulnerability or exploit applicability. The program does not download or execute exploit code.

Research is bounded to eight observed outcomes, six search calls, four results per search, and eight model calls. Open ports receive priority in the observation limit. A scan of more ports can therefore display measurements that do not reach the AI prompt. The total AI timeout includes tool and model calls; increase an existing 15000 ms setting when needed for research.

See the [README's recorded TCP run](../README.md#example-tcp-scan-with-ai-research). Its full console output is under the expandable “Recorded console output” section. The example is recorded model output and may contain incorrect or incomplete conclusions.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `rmap: command not found` | Install with Cargo and add its binary directory to `PATH` |
| Target limit exceeded | Choose a smaller subnet or fewer unique addresses; the limit is 4,096 across the combined selection, after deduplication |
| Scan appears stuck after the banner | Check the startup port count and progress; omitted `--ports` means all 65535 ports. Use a smaller explicit list for a quick scan |
| Waiting after measured results appear | With `--ai`, the separate research phase can run until `RMAP_AI_TIMEOUT_MS` expires |
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
