# Experiment record: SYN versus ACK on the home server

Record created: 2026-11-19.
Last discussion update: 2026-11-21.

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
| Scanner | Separate machine at `192.168.100.8` on the same network | Address reported on 2026-11-21; OS version and path/interface details pending |
| Initial candidate ports | TCP 22 and TCP 1883 | Local listener output and reported agreement between Nmap and rmap |
| First chosen endpoint | `192.168.100.21:1883/tcp` | Chosen on 2026-11-21 to separate probe traffic from SSH management on port 22 |
| Source position | Same LAN as the target | Exact topology and any intermediate filtering still to document |
| Firewall tooling | `/usr/sbin/iptables` found | Active rules, backend and controlling service not yet inspected |
| Initial tool checks | `nft`, `awall`, `python3` and `tcpdump` were not found in the checked server `PATH` | Historical observation; does not establish current package availability |
| Capture tooling, updated | Experimenter now reports tcpdump on both machines | Versions, permissions, capture interfaces and successful recording still to verify |
| Selected service | Experimenter identifies port 1883 as their MQTT service | Process ownership/version not yet recorded; background traffic has not been measured |
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

Packet-level predictions articulated during the 2026-11-21 discussion:

- SYN to the listening service: expect a server SYN/ACK. The scanning machine then
  sends RST as cleanup, aborting the half-open handshake without completing the
  connection. The matching SYN/ACK supports the open observation; the later
  cleanup is separate evidence.
- Unsolicited ACK for a nonexistent connection: expect a server RST directly,
  without a SYN/ACK handshake, assuming the probe and response pass along the path.
- How a response will be associated with the specific outgoing probe: **pending**.

The experimenter initially suggested ICMP Port Unreachable and a filtered result
for the ACK probe, then corrected that packet-level expectation to TCP RST before
any paired measurements were recorded. This is a clarification of the mechanism
underlying the original state prediction, not a measured result or a retrospective
change to a finding.

ICMP Port Unreachable is associated with closed UDP ports; ICMP diagnostics can
also occur along TCP paths, and their type/code matters. TCP has its own reset
mechanism. In rmap ACK mode, the current implementation does not decode ICMP;
tentative `filtered` follows a receive timeout without a matching TCP response.
It does not directly classify a received ICMP error as filtered. Protocol
references: [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122.html#section-3.2.2.1)
and [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.1).

Keep the original predictions if a trial disagrees. Record the discrepancy and
investigate it; date and explain any later revision instead of overwriting this
initial expectation.

## Proposed controls to confirm before measuring

| Item | Initial proposal | Status |
| --- | --- | --- |
| First endpoint | `192.168.100.21:1883/tcp`; examine one port at a time | Chosen; the initial prediction for port 22 remains above for reference |
| Timeout | 1000 ms for each method | To confirm and record with the actual command |
| Concurrency | 1 | To confirm; also record the effective value |
| AI | Disabled | To confirm |
| Services and firewall | Preserve the initial configuration during the baseline | Snapshot and verify before running |
| Capture | Use tcpdump on scanner and target | Availability reported; filters, interfaces, permissions, versions and filenames pending |
| Timing/order | Separate attempts; record their order and timestamps | Follow the paired procedure in the main plan |

This initial comparison does not require stopping a real service. A later
listening/non-listening control should use a separate controllable test service.

## Reasoning and capture preparation: 2026-11-21

The experimenter wants guided reasoning and small tasks, rather than completed
commands or answers supplied in advance. Continue by reviewing their proposed
approach and distinguishing assumptions, predictions and measurements.

### Listener bindings

The experimenter recognized that the listener bound to `192.168.100.21` and the
wildcard IPv4 listener on `0.0.0.0` can receive traffic addressed to the LAN
interface. The destination of the remote probe is still `192.168.100.21`;
`0.0.0.0` is the listener's wildcard binding. Loopback-bound listeners do not
receive these LAN-addressed connections. Firewall rules can impose additional
restrictions, so a binding alone does not prove remote reachability.

### Why capture at both ends?

The experimenter explained that they want to see what the scanner sends, what
the server receives, and what the server sends back. Capture points should let
us compare:

1. The probe leaving the scanner's network interface.
2. The probe arriving at the server's interface.
3. The response leaving the server's interface.
4. The response arriving back at the scanner.

This helps investigate where an expected packet becomes unobserved. Retain
capture-drop statistics: absence from a capture alone is not proof of a network
drop or a particular firewall action. No capture files have been supplied yet.

### Why port 1883?

The experimenter selected 1883 to avoid including the SSH management session on
22. Their initial assumption that MQTT means only their probe packets will appear
was identified as something to verify. Existing clients or applications on the
scanner may also exchange MQTT traffic. Selecting a port or even a host pair does
not guarantee a quiet capture or identify every packet as a scan probe.

### What “TCP portion of the capture filter” means

This refers to the TCP-selection part of a **tcpdump capture-filter expression**,
not Rust code, packet construction, or a new scanner function. Its intended scope
is TCP traffic between `192.168.100.8` and `192.168.100.21` involving port 1883,
retaining both probe and reply directions. No complete filter expression has
been proposed, validated or run yet.

The building blocks discussed were `tcp`, `host ADDRESS`, `port NUMBER`, and
`and`. Without a direction qualifier, a `host` condition matches source or
destination. The next task is for the experimenter to combine these conditions
and explain why the reply would also match. See the
[libpcap capture-filter reference](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-filter.manmisc.in).

The word “portion” leaves room to decide how to retain relevant ICMP diagnostics
as well. A TCP-only filter excludes ICMP. We have not yet agreed on that additional
scope or a final filter, and should not interpret excluded traffic as absent.
Do not restrict capture to only the predicted response flags: unexpected TCP
responses and background traffic are useful evidence too.

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

## Pause and resume point

Paused at the experimenter's request on 2026-11-21. The session established
packet-level predictions, scanner IP, the first test port, and reported capture
tool availability. It did not establish a capture filter, capture configuration,
packet evidence or paired results. No new scan output or firewall changes were
reported during this session.

When resuming, take one small step at a time:

1. Revisit the meaning of a capture-filter expression if needed. Ask the
   experimenter to propose the TCP selection for the two hosts and port 1883,
   keeping both directions, and review their reasoning before running it.
2. Decide how to retain ICMP diagnostics, then verify capture interfaces,
   privileges, versions, output locations and capture/drop statistics.
3. Record the unchanged service/firewall configuration and execution settings;
   inspect background traffic with rmap idle rather than assuming the port is quiet.
4. Only after capture preparation, collect the first SYN/ACK pair, retain raw
   output and captures, and compare actual observations against the predictions.

A disagreement is something to explain, not automatically a scanner bug or proof
of filtering. Actual response correlation, further controls and repeated paired
measurements remain work to do. The existing measurement table stays pending.
