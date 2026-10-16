# Architecture

The project aims to grow into a network scanner inspired by Nmap, written in Rust and extended with optional AI help for interpreting observed services and possible CVE leads. The modules below describe the current TCP connect implementation and keep room for broader scanning capabilities.

CLI input becomes a validated scan configuration. The scanner consumes that configuration and produces structured results. Reporting displays the measured results. When explicitly requested, the AI service receives completed scan results and returns a separate interpretation for reporting. AI connection configuration remains separate from scan configuration.

The types are described here in prose. `ScanMode`, `PortStatus`, `ScanResult`, `AiConfig`, and `AiAnalysis` are implemented; `ScanConfig` remains planned:

- `ScanMode` selects TCP or UDP; the CLI requires exactly one of `--tcp` or `--udp`.
- `ScanConfig` represents the validated target, selected transport, ports, and connection timeout for a scan.
- `PortStatus` represents a classified outcome of one connection attempt, with uncertainty retained where appropriate.
- `ScanResult` holds the measured outcome for a port and any related observations needed for reporting.
- `AiConfig` holds DeepSeek connection settings, model identifier, request timeout, an optional local advisory file path, and a separate Brave Search credential.
- `AiAnalysis` holds an interpretation of completed results plus independently retrieved web sources, research notes and optional local advisory candidates, distinct from measurements.

The scanner must remain independent of the AI service. Reporting should display scan results even if AI configuration, a request, or response handling fails. AI failures must never discard measured results or prevent their display.

`src/cli/` owns argument parsing. `src/scan/mod.rs` is the common entry point and dispatches by `ScanMode`: `tcp.rs` owns the existing TCP scanner, `http.rs` owns its HTTP probe, and `udp.rs` sends sequential empty UDP probes using a fresh local socket per port. A connected UDP socket restricts received datagrams to the selected peer without a handshake. UDP silence is classified as open or filtered; OS-reported refusal is classified as closed. Results and CVE candidates carry their transport so reporting and AI context retain the correct protocol. `src/ai/` owns DeepSeek configuration, a bounded public web search tool, optional local advisory retrieval and interpretation, and `src/model/report.rs` formats both measured results and the separate AI section. Unit tests for private helpers live under `tests/cli/`, `tests/scan/`, `tests/model/`, and `tests/ai/`; the source modules include them only during test builds.
