# Architecture

The project aims to grow into a network scanner inspired by Nmap, written in Rust and extended with optional AI help for interpreting observed services and possible CVE leads. The modules below describe the current TCP connect implementation and keep room for broader scanning capabilities.

CLI input becomes a validated scan configuration. The scanner consumes that configuration and produces structured results. Reporting displays the measured results. When explicitly requested, the AI service receives completed scan results and returns a separate interpretation for reporting. AI connection configuration remains separate from scan configuration.

The types are described here in prose. `PortStatus`, `ScanResult`, `AiConfig`, and `AiAnalysis` are implemented; `ScanConfig` remains planned:

- `ScanConfig` represents the validated target, selected ports, and connection timeout for a scan.
- `PortStatus` represents a classified outcome of one connection attempt, with uncertainty retained where appropriate.
- `ScanResult` holds the measured outcome for a port and any related observations needed for reporting.
- `AiConfig` holds DeepSeek connection settings, model identifier, request timeout, and an optional local advisory file path.
- `AiAnalysis` holds an interpretation of completed results plus independently retrieved CVE advisory candidates, distinct from measured observations.

The scanner must remain independent of the AI service. Reporting should display scan results even if AI configuration, a request, or response handling fails. AI failures must never discard measured results or prevent their display.

`src/cli/` owns argument parsing, `src/scan/` owns TCP connections and HTTP probing, `src/ai/` owns DeepSeek configuration and interpretation, and `src/model/report.rs` formats both measured results and the separate AI section. Unit tests for private helpers live under `tests/scan/` and `tests/ai/`; the source modules include them only during test builds.
