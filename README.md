# rmap (ALPHA version)

`rmap` aims to be a network scanner inspired by Nmap, written in Rust and extended with AI interpretation. Its goal is to find and describe exposed services, then help a user understand what observed service versions might mean, including possible CVE leads. Scan measurements and AI conclusions stay separate so the tool can show what it observed without presenting a model's guess as a fact.

The current implementation scans selected TCP or UDP ports on one IPv4 address, collects limited banners, probes HTTP on port 80, and can ask DeepSeek to research public CVEs and exploit references using a web search tool. It does not yet offer Nmap's range of scan methods, host discovery, concurrent scanning, broad service fingerprinting, or exhaustive vulnerability detection. Building it is also a way to learn Rust networking, I/O, timeouts, and error handling.

## How a run works

1. The CLI validates an IPv4 target, a scan mode (`--tcp` or `--udp`), a comma-separated list of ports, and a positive timeout.
2. The common scanner entry point dispatches to the selected transport. UDP sends an empty datagram to each selected port and waits for a response. For each TCP port, the scanner attempts a TCP connection and records its elapsed connection time and outcome in a `ScanResult`.
3. On an open port other than 80, it reads a passive banner. On open port 80, it sends an HTTP `HEAD` probe using a separate connection.
4. The report prints the measured results before any optional AI work.
5. With `--ai`, the program sends bounded observations to DeepSeek through Rig. With a Brave Search key configured, the agent researches CVEs, vendor and distribution advisories, and Exploit-DB references using a public web search tool. An optional local advisory file can supplement the web evidence. Interpretation and retrieved source links appear separately from measurements. AI or search failures leave the scan report visible.

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

### Example TCP scan with AI research

This recorded run uses `192.0.2.21` as an anonymized documentation address. Replace it with your authorized target. AI output is retained as recorded, including incomplete text; its CVE and exploit applicability claims are generated interpretations, not verified findings. Timings, search results, and model output vary between runs.

```bash
rmap --tcp --target 192.0.2.21 --ports 80,22,21,8080,443,111,139,445,2409,8000 --timeout-ms 1000 --ai
```

<details>
<summary>Recorded console output: scan measurements, AI interpretation, and web sources</summary>

```text
      \       /
   ___ \_____/ ___
  /   \(o   o)/   \
  \___/  ___  \___/
      \ (___) /
     __\_____/__
    / /       \ \
   (_/         \_)

  RRRRR   M   M    AAA    PPPPP
  R    R  MM MM   A   A   P    P
  R    R  M M M  AAAAAAA  P    P
  RRRRR   M   M  A     A  PPPPP
  R   R   M   M  A     A  P
  R    R  M   M  A     A  P

  v0.2.0 - Rust network scanner with optional AI interpretation.

Scan results for 192.0.2.21

PORT      STATE          SERVICE       ELAPSED  DETAIL
----------------------------------------------------------------------------------
80/tcp    open           http         96.60 ms  Server: Apache/2.4.68 (Debian)
22/tcp    open           ssh           3.44 ms  SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
21/tcp    open           -            55.19 ms  220 (vsFTPd 3.0.5)
8080/tcp  filtered       -          1000.83 ms  connection timed out
443/tcp   filtered       -          1000.26 ms  connection timed out
111/tcp   open           -            75.99 ms  read timed out
139/tcp   open           -            83.43 ms  read timed out
445/tcp   open           -            19.63 ms  read timed out
2409/tcp  filtered       -          1001.12 ms  connection timed out
8000/tcp  open           -            42.27 ms  read timed out

filtered = connection timed out; filtering is unconfirmed.

╭─ AI INTERPRETATION ───────────────────────────────────────────────────────
│  ## Observed services
│  - 80/tcp open — Apache/2.4.68 (Debian) [HTTP banner]
│  - 22/tcp open — OpenSSH_10.0p2 Debian-7+deb13u4 [SSH banner]
│  - 21/tcp open — vsFTPd 3.0.5 [FTP banner]
│  - 111, 139, 445, 8000/tcp open — no banner (read timeout); 8080/tcp
│  filtered. Service identity unconfirmed; not researched.
│
│  ## Possible CVEs (applicability + sources)
│  - **Apache 2.4.68**: Apache's own advisory page lists issues affecting
│  "2.4.0 through 2.4.68" (e.g., mod_heartmonitor NULL deref;
│  mod_session_cookie info exposure; mod_dav_fs integer overflow;
│  mod_userdir path equivalence). These are *fixed in a later release*, so
│  2.4.68 may be affected depending on module/config. Source:
│  https://httpd.apache.org/security/vulnerabilities_24.html . A Tenable
│  plugin references a "prior to 2.4.68" advisory set (CVE-2026-44119
│  mod_ssl OCSP over-read; CVE-2026-49975 HTTP/2 Bomb) — those affect
│  versions *before* 2.4.68, so likely not applicable to this host. Source:
│  https://www.tenable.com/plugins/nessus/319665 . Debian may backport
│  fixes; verify against Debian tr
│  - **vsFTPd 3.0.5**: CVE-2025-14242 — DoS via integer overflow in `ls`
│  parameter parsing; requires authenticated FTP access (CVSS 6.5, PR:L).
│  Debian tracker lists affected vsftpd source versions (3.0.3-12/-13/-13.1)
│  — applicability depends on the Debian package revision, not just the
│  3.0.5 banner. Sources:
│  https://access.redhat.com/security/cve/cve-2025-14242 ,
│  https://osv.dev/vulnerability/DEBIAN-CVE-2025-14242 ,
│  https://www.sentinelone.com/vulnerability-database/cve-2025-14242/ .
│  - **OpenSSH 10.0p2**: No specific CVE retrieved for this exact version.
│  Repology/CVE Details pages exist but returned no concrete applicable CVE
│  in snippets. Sources:
│  https://repology.org/project/openssh/cves?version=10.0p2 ,
│  https://www.cvedetails.com/version/1976097/Openbsd-Openssh-10.0.html . No
│  conclusion drawn.
│
│  ## Public exploit references (applicability + sources)
│  - vsftpd 3.0.3 Remote DoS — https://www.exploit-db.com/exploits/49719 —
│  reported version 3.0.3; not the observed 3.0.5, so likely not applicable.
│  - vsftpd 2.3.4 Backdoor (CVE-2011-2523) —
│  https://www.exploit-db.com/exploits/49757 — version 2.3.4; not applicable
│  to 3.0.5.
│  - vsftpd 2.0.5 CWD DoS — https://www.exploit-db.com/exploits/5814 —
│  version 2.0.5; not applicable.
│  - Apache 2.4.66 mod_http2 Double-Free DoS (CVE-2026-23918) —
│  https://www.exploit-db.com/exploits/52577 — reported 2.4.66; not the
│  observed 2.4.68.
│  - Apache 2.4.x Buffer Overflow (<2.4.51) —
│  https://www.exploit-db.com/exploits/51193 — not applicable to 2.4.68.
│  - No Exploit-DB entry retrieved matching vsFTPd 3.0.5 or Apache 2.4.68
│  exactly.
│
│  ## Verification
│  - Banners are self-reported and may be spoofed or patched; version
│  strings alone do not prove vulnerability.
│  - Confirm Apache module/config exposure and Debian package revision
│  (`dpkg -l apache2`) against the Debian tracker before concluding.
│  - For vsftpd, confirm the Debian package revision (CVE-2025-14242
│  applicability is revision-specific) and whether anonymous/authenticated
│  FTP is enabled.
│  - OpenSSH 10.0p2: no applicable CVE found in retrieved evidence — absence
│  of evidence, not proof of safety.
│  - Ports 111/139/445/8000 returned no banner; service identity and any
│  CVEs are unverified. 8080 filtered — no conclusion.
│  - No local advisory candidates were supplied; all findings above are
│  candidate-level from search snippets, not confirmed exploitation.
│
│  WEB RESEARCH
│  6 of at most 6 web searches performed; results are not exhaustive.
│  Information on source package apache2 - Security Bug Tracker
│  Source:
│  https://security-tracker.debian.org/tracker/source-package/apache2
│
│  Apache HTTP Server 2.4 vulnerabilities - The Apache HTTP Server Project
│  Source: https://httpd.apache.org/security/vulnerabilities_24.html
│
│  Apache Http Server : Security vulnerabilities, CVEs
│  Source:
│  https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/Apache-Http-Server.html
│
│  Apache 2.4.x
│  Source: https://www.tenable.com/plugins/nessus/319665
│
│  Known vulnerabilities in vsftpd 3.0.5
│  Source: https://www.cybersecurity-help.cz/vdb/soft/vsftpd/vsftpd/3.0.5/
│
│  Vsftpd Project Vsftpd 3.0.5 Observation Footprint | Bitsight
│  Source: https://www.bitsight.com/groma-explorer/vsftpdproject/vsftpd/305
│
│  RHSA-2026:0605 - Security Advisory
│  Source: https://access.redhat.com/errata/RHSA-2026:0605
│
│  Cve
│  Source: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=vsftpd
│
│  Openbsd Openssh 10.0 security vulnerabilities, CVEs
│  Source:
│  https://www.cvedetails.com/version/1976097/Openbsd-Openssh-10.0.html
│
│  Cisco Bug: CSCws05129 - Vulnerabilities in openssh 10.0p2
│  Source: https://bst.cisco.com/quickview/bug/CSCws05129
│
│  openssh vulnerabilities - Repology
│  Source: https://repology.org/project/openssh/cves?version=10.0p2
│
│  Cve
│  Source: https://www.cve.org/CVERecord/SearchResults?query=openssh
│
│  vsftpd 3.0.3 - Remote Denial of Service - Multiple remote Exploit
│  Source: https://www.exploit-db.com/exploits/49719
│
│  Gopherd 3.0.5 - FTP Gateway Remote Overflow - Linux remote Exploit
│  Source: https://www.exploit-db.com/exploits/84
│
│  vsftpd 2.3.4 - Backdoor Command Execution - Unix remote Exploit
│  Source: https://www.exploit-db.com/exploits/49757
│
│  vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption - Linux
│  dos Exploit
│  Source: https://www.exploit-db.com/exploits/5814
│
│  CVE-2025-14242 - Red Hat Customer Portal
│  Source: https://access.redhat.com/security/cve/cve-2025-14242
│
│  CVE-2025-14242: vsftpd Denial of Service Vulnerability
│  Source:
│  https://www.sentinelone.com/vulnerability-database/cve-2025-14242/
│
│  OSV - Open Source Vulnerabilities
│  Source: https://osv.dev/vulnerability/DEBIAN-CVE-2025-14242
│
│  Apache HTTP Server 2.4.66 - 'mod_http2' Double-Free Denial of Service -
│  Multiple webapps Exploit
│  Source: https://www.exploit-db.com/exploits/52577
│
│  Apache 2.4.x - Buffer Overflow - Multiple webapps Exploit
│  Source: https://www.exploit-db.com/exploits/51193
│
│  Apache 2.4.17
│  Source: https://www.exploit-db.com/exploits/46676
│
│  Apache
│  Source: https://www.exploit-db.com/exploits/42745
│
│  Candidate matches require manual verification, including vendor fixes.
```

</details>

## Optional AI interpretation

Add `--ai` to ask DeepSeek to explain the completed scan:

```bash
cargo run -- --tcp --target 127.0.0.1 --ports 22,80,8080 --timeout-ms 1000 --ai
```

AI is off by default. With `--ai`, DeepSeek receives at most eight port observations (open ports first), including service labels, states, and up to 160 characters of each banner, HTTP header, or error. A label such as `ssh` or an unknown label does not prevent research: the agent uses the product/version text in the observation, such as `220 (vsFTPd 3.0.5)`.

For live research, configure `RMAP_SEARCH_API_KEY` with a [Brave Search API key](https://api-dashboard.search.brave.com/documentation/guides/authentication). This is a separate credential from the DeepSeek key. The Rig agent can call `search_web` to:

- Search the general public web for the observed product/version and related CVEs.
- Compare CVE.org, NVD, vendor and distribution advisories, and other returned sources for affected versions, backports, prerequisites, and conflicting claims.
- Search `site:exploit-db.com/exploits` for potentially relevant public exploit or proof-of-concept entries, providing titles, links, reported versions, prerequisites when available, and reasons they may or may not apply.

Web research uses search result snippets and additional excerpts, not full-page downloads. The agent must cite retrieved links and disclose missing evidence. Public exploit availability and a matching banner do not establish that a target is vulnerable. For example, [Debian identifies CVE-2025-14242 as affecting code introduced by a Red Hat specific patch](https://security-tracker.debian.org/tracker/CVE-2025-14242), so `vsFTPd 3.0.5` alone is insufficient to establish applicability. The application retrieves references; it does not download or execute exploit code.

Each analysis allows up to six web searches, four results per search, and eight model calls. Results are bounded and are not an exhaustive search of the internet. A search request is limited to 15 seconds and 512 KiB of response data. `RMAP_AI_TIMEOUT_MS` bounds the entire model/tool session; the default is 60000 ms. If your existing `.env` sets 15000, increase it to allow time for research. Search rate limits, unavailable pages, missing version information, and the call budget can leave some products unresearched; the report displays research failures and retrieved source links separately from the generated interpretation.

When the search key is missing, the report explicitly says that live research is unavailable. Interpretation can still use scan observations and optional local advisories, but the model cannot browse the web using its DeepSeek API key alone. With `--ai` and search configured, product/version queries are sent to Brave Search and the returned evidence is sent to DeepSeek. The prompt instructs the agent to search using product/version names and CVE IDs, excluding target addresses, credentials, and full raw banners. Banners, advisory text, and search results are untrusted data and must never be treated as instructions.

An optional local UTF-8 TSV file can supplement live research through `RMAP_CVE_FILE`. Each record has five tab-separated fields:

```text
CVE-ID<TAB>product<TAB>exact-version<TAB>https://source-url<TAB>description
```

The reader ignores lines beginning with `#`, limits the file to 1 MiB, and selects at most five exact product/version text matches. It recognizes slash, underscore, and space separators, including `vsFTPd 3.0.5`. This file is not required for web research; local lookup errors are reported without preventing the agent from searching online. Advisory matches remain candidates requiring independent verification.

### AI configuration

Copy [`.env.example`](.env.example) to a local `.env` in the directory where you run `rmap`, or export the same names in your shell. The application reads `.env` only when `--ai` is used. Exported environment variables take precedence over values in the file. `.env` and other local `.env.*` files are Git-ignored; `.env.example` is tracked.

| Variable | Meaning |
| --- | --- |
| `RMAP_AI_BASE_URL` | Optional DeepSeek API base URL; blank uses Rig's default endpoint |
| `RMAP_AI_API_KEY` | Required DeepSeek API key |
| `RMAP_AI_MODEL` | Required model identifier chosen by the user |
| `RMAP_AI_TIMEOUT_MS` | Maximum duration of the complete AI research session in milliseconds; defaults to `60000` |
| `RMAP_SEARCH_API_KEY` | Brave Search API key for live CVE, advisory, and Exploit-DB searches |
| `RMAP_CVE_FILE` | Optional path to your local advisory TSV file |

Existing `RUST_NMAP_*` variables remain accepted as compatibility aliases. Nonempty exported values take precedence over file values; within each source, `RMAP_*` takes precedence over its legacy alias. Your existing local `.env` can keep its previous variable names.

The AI request uses DeepSeek's non-thinking mode to produce a short final answer. The application does not print the API key or provider response body. Configuration or model errors are reported after the measured results; search and optional local lookup errors appear as research notes. Keep credentials out of commits, logs, reports, and shared terminal output.

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
    ├── retrieval.rs    Optional local CVE advisory matching
    ├── service.rs      Research prompt and Rig tool orchestration
    └── web.rs          Bounded Brave Search tool and evidence capture

tests/
├── cli/                Scan mode and argument validation tests
├── scan/               TCP, UDP classification, and HTTP unit tests
├── model/              Report formatting tests
└── ai/                 Configuration, retrieval, search, and service unit tests
```

The tests are in separate files under `tests/`, but each source module includes its tests only in a test build. This keeps private helper functions private while making the test files easy to find. See [usage and troubleshooting](docs/usage.md), [architecture](docs/architecture.md), and [AI integration](docs/ai-integration.md) for more detail.

## Local checks

The following commands format, test, lint, and build without making a live scan or DeepSeek request:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked -- -D warnings
cargo build --release --locked
```
