# Experiment record: SYN versus ACK on the home server

Record created: 2026-11-19.

Status: **predictions recorded; preliminary observations supplied by the
experimenter; paired SYN/ACK measurements and packet evidence pending**.

This file records the experimenter's setup and predictions. It is the baseline
qualification for the [SYN-versus-ACK experiment](syn-vs-ack.md), before introducing
controlled filtering. It is separate from the [first-run guide](alpine-first-run.md).
The assistant has not scanned the server or changed its configuration.

## Question for this baseline

For the server's LAN-accessible TCP listeners, do separately measured SYN and ACK
outcomes agree with the predictions below?

The first comparison keeps the target, selected port, source position and server
configuration fixed while changing the probe method. Controlled firewall changes
and the broader filtering hypothesis belong to later conditions.

## Setup established so far

| Item | Recorded information | Evidence or remaining uncertainty |
| --- | --- | --- |
| Target | Experimenter's own Alpine Linux server | Confirmed by the experimenter; release/kernel version not recorded |
| Target address | `192.168.100.21/24` on `wlan0` | Supplied `ip -4 addr show` output |
| Scanner | Separate machine on the same network | Reported by the experimenter; scanner IP, OS version and path/interface details pending |
| Initial candidate ports | TCP 22 and TCP 1883 | Local listener output and reported agreement between Nmap and rmap |
| Source position | Same LAN as the target | Exact topology and any intermediate filtering still to document |
| Firewall tooling | `/usr/sbin/iptables` found | Active rules, backend and controlling service not yet inspected |
| Other tooling | `nft`, `awall`, `python3` and `tcpdump` were not found in the checked `PATH` | Preliminary tool checks; current installation/availability still to establish |
| Container networking | Docker bridges were present in the supplied interface output | Whether either selected service is containerized is unknown |
| Project source version | Workspace package declares `0.6.0` | Exact revision, dirty-tree state and executed binary version must be recorded for each run |

The vulnerable VM at `192.168.56.101` was considered earlier and is outside this
baseline's scope. Its commands or observations must not be mixed with this server's
records.

## Preliminary observations already gathered

The experimenter supplied these local listening-socket observations from
`netstat -lnt`:

```text
tcp        0      0 192.168.100.21:1883     0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:9092          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8081          0.0.0.0:*               LISTEN
```

An additional row ending in `:::22` was supplied incompletely; retain the full row
when collecting the original output. Process ownership was not included.

The experimenter also reports that Nmap and rmap agreed on ports 22 and 1883 being
open remotely. Their exact commands, scan methods, versions, timestamps and raw
outputs have not been supplied. Treat this as preliminary reconnaissance, not as
a documented paired SYN/ACK trial or packet-level validation.

These are several local listeners, with two reported reachable from the LAN.
The specific LAN binding, wildcard IPv4 binding and loopback bindings have
different scopes. The listener snapshot is evidence of socket state at that
moment; it does not establish the firewall's treatment of unsolicited ACK probes.
Port numbers alone do not establish service identity or software version.

## Predictions declared before the paired experiment

The experimenter's prediction: SYN should show both selected ports as open;
ACK should show both as unfiltered.

| Target endpoint | Predicted SYN state | Predicted ACK state | Measurement status |
| --- | --- | --- | --- |
| `192.168.100.21:22/tcp` | `open` | `unfiltered` | Pending |
| `192.168.100.21:1883/tcp` | `open` | `unfiltered` | Pending |

The ACK prediction assumes the unsolicited probe and its response can pass along
the path. This assumption has not been verified. Agreement on a SYN outcome does
not establish how ACK traffic will be handled. These predictions are not findings.

Packet-level predictions remain for the experimenter to articulate:

- Response flags/evidence expected to support the SYN prediction: **pending**.
- Response flags/evidence expected to support the ACK prediction: **pending**.
- How a response will be associated with the specific outgoing probe: **pending**.

Keep the original predictions if a trial disagrees. Record the discrepancy and
investigate it; date and explain any later revision instead of overwriting this
initial expectation.

## Proposed controls to confirm before measuring

| Item | Initial proposal | Status |
| --- | --- | --- |
| First endpoint | Choose one of 22 or 1883; examine one port at a time | Choice pending |
| Timeout | 1000 ms for each method | To confirm and record with the actual command |
| Concurrency | 1 | To confirm; also record the effective value |
| AI | Disabled | To confirm |
| Services and firewall | Preserve the initial configuration during the baseline | Snapshot and verify before running |
| Capture | Record the outgoing probe and response on scanner and target | Tooling, interfaces and filenames pending |
| Timing/order | Separate attempts; record their order and timestamps | Follow the paired procedure in the main plan |

This initial comparison does not require stopping a real service. A later
listening/non-listening control should use a separate controllable test service.

## Measurement log

No dedicated paired trial has been recorded here yet. Add actual observations
without replacing the prediction table.

| Trial/pair ID | Endpoint | Method | Observed state | Elapsed time | Diagnostic | Evidence files |
| --- | --- | --- | --- | --- | --- | --- |
| Pending | Pending | Pending | Not recorded | Not recorded | Not recorded | Not collected |

For each trial, retain:

- Code revision and local changes, binary version, Rust toolchain, and OS/kernel versions.
- Source/target IPs, interfaces, topology, service bindings/processes and firewall snapshot.
- Exact command, selected scope, timeout, requested/effective concurrency, execution order,
  start/finish timestamps and process exit status.
- Unedited stdout/stderr and packet capture files from each capture point, including
  capture/drop statistics and relevant packet references.
- Probe/response header fields needed for correlation, obtained from the captures;
  the console does not export those raw fields.
- Separate notes for local setup/send/receive failures, silence, unexpected packets
  and any change in the lab condition.

Keep private captures and configuration artifacts outside source control; record
their locations here without credentials. No experimental conclusions are recorded.

## Next reasoning step

Before collecting the first pair, state which packet evidence would support each
predicted label. Then choose the first endpoint and establish how that evidence
will be captured. A disagreement between prediction and observation is something
to explain, not automatically a scanner bug or proof of filtering.
