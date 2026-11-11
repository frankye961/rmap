# Experiment 1: SYN and ACK observations under controlled filtering

Status: **design only; no experimental measurements recorded here**.
SYN scanning exists in rmap. ACK is an unwired scaffold; there is no working
`--ack` command yet. This document defines the experiment before its implementation.

## Research question

**What additional evidence does ACK probing provide when SYN probing receives
no response, under controlled TCP filtering?**

The unit of comparison is one SYN attempt and one ACK attempt against the same
target address and port under the same lab condition. Record each observation
separately, including unsuccessful attempts.

## Hypothesis and possible contrary evidence

H1: when the lab drops SYN probes but permits unsolicited ACK probes and their
responses, ACK attempts will receive matching resets more often than SYN attempts
receive matching responses. SYN alone will leave this difference unobserved.

Support requires captured packets and repeated measurements, not an expected
output table. If verified ACK delivery repeatedly produces no reset, or the
measured response rates do not differ, the results do not support this prediction
for that configuration. Investigate the discrepancy and report it rather than
silently excluding those trials.

An ACK reset does not predict whether an application is listening. It also does
not prove that a new TCP connection would be permitted. Nmap makes this distinction
with its `unfiltered` state; its [ACK scan documentation](https://nmap.org/book/scan-methods-ack-scan.html)
is the initial reference for this experiment.

## What this study contributes initially

This is a replication and instrument-validation study of known behavior. It does
not establish a new scanning technique. Its first deliverables are a reproducible
lab description, paired observations, packet evidence, and an account of which
conclusions the observations support. A later policy evaluator can use this
evidence without treating every timeout as successful segmentation enforcement.

## Lab design and ground truth

Use a scanner, a controlled filtering boundary, and a target. These can be
isolated virtual machines or network namespaces. Record the actual arrangement
before collecting data; no topology or firewall has been configured by this plan.

```text
scanner/source position  -->  controlled filter  -->  target/service
```

Use one fixed TCP port, for example 18080, with a listener that can be started
and stopped independently of filtering. Keep the selected source position fixed
for this first study. Broader service identification and AI are outside this
experiment.

Ground truth means the configuration independently verified by the experimenter:

- Whether the target has a listener on the selected address and port.
- Which probes and responses the boundary and host firewalls permit or drop.
- Whether connection tracking would discard an unsolicited ACK before the
  intended experimental rule takes effect.
- Whether a connection with the probe's endpoint tuple already exists.

Retain configuration snapshots and packet captures on the scanner and target,
plus the filtering boundary where practical. A scanner-side capture alone cannot
establish that a reset came from the target rather than a middlebox. Unexpected
ICMP messages, drops, or resets are evidence to retain and investigate.

## Conditions and expected observations

These predictions assume an ordinary target TCP implementation and verified
return-path delivery. They are **expected outcomes, not measured findings**.
The filter conditions describe unsolicited probe handling, not just a broad
policy label such as "stateful firewall".

| ID | Known lab condition | Expected SYN observation | Expected ACK observation | Supported interpretation |
| --- | --- | --- | --- | --- |
| C1 | Listener active; both probes permitted | Matching SYN/ACK | Matching RST | SYN supports an open-port observation; ACK does not identify listener state |
| C2 | No listener; both probes permitted | Matching RST/ACK | Matching RST | SYN supports a closed-port observation; ACK again does not identify listener state |
| C3 | Listener active; both probes silently dropped | No matching response by deadline | No matching response by deadline | The scanner has no response evidence; configuration/captures establish the lab's cause |
| C4 | Listener active; SYN dropped; ACK and its response permitted | No matching response by deadline | Matching RST | The path handles the two probe types differently; no successful connection is established by ACK |
| C5 | Listener active; ACK dropped; SYN and its response permitted | Matching SYN/ACK | No matching response by deadline | ACK silence alone does not establish that SYN connections are blocked |

The reset behavior is grounded in [RFC 9293, section 3.5.2](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.2).
Use [Nmap's SYN/ACK filtering discussion](https://nmap.org/book/determining-firewall-rules.html)
as background; verify its assumptions in this lab rather than copying its findings.

## Pilot procedure and controls

After ACK construction, correlation, timeout handling, and reporting pass offline
tests, use this initial pilot plan:

1. Record the code revision, uncommitted changes, build version, Rust toolchain,
   operating systems, topology, interfaces, service settings and firewall rules.
2. Verify C1 and C2 first. Investigate disagreement before interpreting filtering
   experiments; keep a record of failed qualification attempts.
3. For each condition, collect 20 SYN/ACK pairs with one attempt per method,
   one selected port, concurrency 1 and a 1000 ms probe timeout. These are initial
   pilot choices, not defaults established by an experiment or a power analysis.
4. Alternate pair order: SYN then ACK, followed by ACK then SYN. Leave at least
   one second between attempts and record actual send/receive timestamps. Record
   condition order and repeat the controls after the filtering conditions.
5. Retain stdout, stderr and captures for every attempt. Record local failures
   separately from attempts sent without a response. A setup failure is not a timeout.
6. Compare the report with captures, then compare observations across methods.
   Report deviations from the plan and unexpected outcomes explicitly.

Hold target, port, source position, timeout, concurrency, service implementation,
and return-path configuration fixed within a condition. Record changing load,
rate limiting, packet loss and capture loss where observed. Do not pool different
conditions or code revisions into one response rate without identifying them.

Nmap can provide an additional reference measurement. Record its version and
exact options separately: its scheduling and retransmission behavior may differ
from rmap. Agreement with Nmap is useful corroboration, not independent ground truth.

## Records and measurements

Keep records manually outside the application for now; durable export is not
implemented. For each attempt retain:

- Pair/run ID, condition, method, execution order and start/finish timestamps.
- Actual source/target addresses and ports, probe sequence and acknowledgment
  fields, timeout and effective concurrency.
- Observed response flags, correlation result, elapsed time, error/stop reason,
  printed state, and capture filenames or packet references.
- A separate interpretation and the evidence supporting it.

Measure matched-response counts/rates for each method and condition, the fraction
of pairs with different response outcomes, local-failure counts, and variation
across repeated pairs. Give denominators explicitly; distinguish all scheduled
attempts from attempts confirmed sent. Record elapsed times and actual probe
counts as cost observations rather than claiming a performance improvement.

For C4, the primary comparison is ACK matched-reset rate versus SYN matched-response
rate. For C1/C2, check whether ACK observations distinguish listener state at all.
Do not turn ACK resets into open/closed claims or timeouts into confirmed firewall
enforcement. This small pilot cannot establish behavior across all operating
systems, devices, packet-loss levels or network positions.

## Results log

| Condition | Completed pairs | SYN observations | ACK observations | Evidence location | Interpretation |
| --- | --- | --- | --- | --- | --- |
| C1 | Not collected | Pending | Pending | Pending | Pending |
| C2 | Not collected | Pending | Pending | Pending | Pending |
| C3 | Not collected | Pending | Pending | Pending | Pending |
| C4 | Not collected | Pending | Pending | Pending | Pending |
| C5 | Not collected | Pending | Pending | Pending | Pending |

## Reading and first completion criterion

Start with the Nmap ACK explanation, then sections 2 and 4 of
[Paxson's Strategies for Sound Internet Measurement (2004)](https://conferences.sigcomm.org/imc/2004/papers/p263-paxson.pdf)
for instrument errors, metadata, calibration and reproducible analysis. Use
[the Dagstuhl reproducibility guide (2019)](https://arxiv.org/abs/1902.02165)
to plan the artifacts another person would need to repeat the study.

The first research step is complete when the question, hypothesis and expected
conditions are understood, and the actual lab topology, listener and filtering
boundary have been chosen and written down. Measurements remain pending until
the ACK implementation is ready and the controlled runs have actually occurred.
