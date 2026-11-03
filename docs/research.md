# Research direction

rmap has become the author's research project in networking and cybersecurity,
while continuing to support learning Rust and network programming. It keeps
its identity as a Rust scanner inspired by Nmap, with optional AI interpretation.

The central question is how to collect network observations and reach useful
security conclusions while preserving evidence and uncertainty. A successful
connection establishes observed connectivity at a particular moment. Protocol
responses add service evidence. Software banners are self-reported, and neither
an open port nor an AI-generated CVE candidate establishes exploitability.

## Current experimental foundation

Version 0.5.2 provides TCP connect, UDP, and Linux IPv4 SYN scanning; bounded
concurrent scheduling; passive banner recognition; HTTP/HTTPS probes; and TCP
portmapper v2 NULL identification. Scan measurements and AI interpretation use
separate models. Offline tests cover byte encoding, malformed responses,
timeouts, scheduling, and preservation of open results when identification fails.

These tests establish behavior for their fixtures. They do not measure accuracy
against real networks, validate live TLS or RPC interoperability, or establish
performance under high concurrency. The current output is a console report;
durable assessment records and comparison tooling are future work.

## Next controlled experiment

Research question: can rmap distinguish an open TCP port from a successfully
identified RPC service when identification fails?

Use a small authorized lab with known service configurations. The following are
expected conditions and outcomes, not measured findings:

| Known condition on TCP port 111 | Expected result | Limit of the conclusion |
| --- | --- | --- |
| A service answering the portmapper v2 NULL call | Open, with `rpcbind` and protocol version 2 in the detail | The response does not identify daemon software or prove authentication |
| A listening service returning malformed RPC bytes | Open, with an identification diagnostic and unknown service | A parser rejection does not establish absence of every RPC implementation |
| A listening service accepting connections but staying silent | Open, with an RPC read timeout and unknown service | Silence does not establish a service identity |
| No listener, with an explicit TCP refusal | Closed, without an RPC probe | Rejection alone does not identify its network or host cause |

Retain the initial connection observation and inspect a packet capture to check
that the reply XID matches the request. Record identification failures separately
from port state. The initial connection and the later RPC probe use different
connections, so a service or path can change between them.

## Reproducibility checklist

Keep an experiment record outside the current application with:

- Code revision, dirty-tree changes, package version, and Rust toolchain.
- Lab topology, operating systems, and actual source network position.
- Target service and package versions, configuration, and firewall rules.
- Exact CLI commands, selected target/port scope, and timeout.
- Requested concurrency and the effective limit shown during the run.
- Start/finish times, stdout and stderr, and packet captures where applicable.
- Known lab conditions, expected outcomes, measured outcomes, and discrepancies.

Avoid credentials in shared records. A declared source label by itself would
not change routing or prove where a probe originated. Plan repeated experiments
under controlled conditions before drawing performance or reliability conclusions.

## Planned assessment direction

The BreachMap-inspired assessment concept remains a later integration within
rmap's existing application and scanning engine:

1. Assessment context and exact connectivity-policy evaluation, with conclusions
   separate from measurements and explicit inconclusive outcomes.
2. Export/import of reproducible assessment records and comparison across source
   positions.
3. Before/after remediation comparison with evidence of what changed.
4. Controlled research experiments and richer service evidence.

These are planned capabilities. The current release does not implement policy
input, run-context records, record export/import, cross-position comparison, or
remediation comparison. Service enumeration, NFS/SMB identification, OS detection,
and additional scan techniques are also separate future development choices.
