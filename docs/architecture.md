# Planned architecture

CLI input becomes a validated scan configuration. The scanner consumes that configuration and produces structured results. Reporting displays the measured results. When explicitly requested, the AI service receives completed scan results and returns a separate interpretation for reporting. AI connection configuration remains separate from scan configuration.

The intended types are described here in prose; none are implemented yet:

- `ScanConfig` represents the validated target, selected ports, and connection timeout for a scan.
- `PortStatus` represents a classified outcome of one connection attempt, with uncertainty retained where appropriate.
- `ScanResult` holds the measured outcome for a port and any related observations needed for reporting.
- `AiConfig` holds the provider address, optional credential as required by that provider, model identifier, and request timeout.
- `AiAnalysis` holds an interpretation of completed results, distinct from the measured observations.

The scanner must remain independent of the AI service. Reporting should display scan results even if AI configuration, a request, or response handling fails. AI failures must never discard measured results or prevent their display.
