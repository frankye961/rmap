# RPC identification and learning notes

Implemented in rmap **0.5.2** as part of the network and cybersecurity
[research project](research.md). The behavior described here is supported by
offline fixtures; live protocol validation remains separate work.

The first RPC goal is identifying a TCP service that successfully answers a
portmapper v2 NULL call. It does not include enumerating registered services,
NFS identification, or RPC over UDP. TCP connect scans automatically select the
probe for confirmed-open port 111; no additional CLI flag is needed.

## What is implemented

- `src/scan/rpc.rs` builds the 40-byte call for program 100000, version 2,
  procedure NULL, using AUTH_NONE. `frame_rpc_record` adds one final-fragment
  TCP record marker.
- `decode_record_marker` extracts each fragment's final flag and length.
  `read_rpc_record` reads complete fragments across short reads, removes markers,
  and assembles their payloads under one deadline and total-byte limit.
- `rpc::probe` connects, writes the complete request, and reads the assembled
  reply under the same absolute deadline. Partial writes are handled by
  `write_all`; EOF, timeout, and I/O errors return diagnostics.
- The reply validator expects a complete RPC message body without TCP record
  markers. It checks the request XID, REPLY message type, MSG_ACCEPTED status,
  verifier length and bounds, zero-valued XDR padding, procedure SUCCESS,
  and the absence of trailing NULL result bytes. Parsing the verifier does not
  authenticate the server.
- `is_rpc_candidate` selects port 111 as the initial TCP probe hint. Neither
  this port nor an open connection is sufficient evidence of RPC identity.
- `response_information` validates before mapping. The existing mapper's
  `map_portmapper_service` creates the `rpcbind` service label and an observation
  containing program 100000, portmapper protocol version 2, and NULL success.
  Product and software version stay unknown: protocol version 2 is not a
  daemon release number. The label does not establish the server implementation.
- `tcp::apply_rpc_probe_result` accepts a completed exchange's reply body or
  error. It handles only open TCP-connect results on the candidate port.
  Success applies structured service information. Failure appends an RPC
  diagnostic without removing any earlier service identification. Both paths
  preserve connection state, elapsed time, socket error, passive banner bytes,
  and existing observation text. The existing console renderer can display
  the mapped service and protocol observation without a separate RPC report.

## How the scanner calls the probe

After the initial TCP connection confirms port 111 is open, `scan_port` drops
that stream and calls `collect_rpc`. This helper creates a random XID using
the existing `getrandom` dependency, computes an absolute deadline from the scan
timeout, and passes both to `rpc::probe`. It enforces a 4096-byte reply limit.
Closing the first connection before the RPC connection preserves the scheduler's
descriptor budget. A random-source failure is reported without making a probe.

The completed exchange result and original XID reach `apply_rpc_probe_result`.
The handler validates and maps the body; receiving bytes alone never establishes
identity. Record markers are excluded from validation. Failure preserves the
original open state, connection timing, and any earlier identification. The
normal runtime path does not collect a passive banner first on port 111, so
`ScanResult.banner` remains absent there. The handler still preserves existing
passive evidence if supplied by another caller.

The initial connection and identification have separate timeout budgets;
connect, write, and fragment reads within the RPC exchange share one deadline.
The report's elapsed measurement is the initial TCP connection time. Other
non-HTTP/HTTPS TCP ports keep passive banner collection. HTTP/HTTPS selection,
UDP, SYN, CLI syntax, and AI behavior are unchanged by RPC identification.

## Remaining validation and later scope

The basic request/response path is wired, but a controlled-lab test against a
real portmapper service remains unperformed. In an authorized lab, retain the
exact command, code revision, service configuration, report, and a packet capture
when checking a listening service and malformed/absent responses. Compare the
request XID to the response, and verify that identification errors do not erase
the measured open result. These are proposed checks, not experimental findings.

Registered-program enumeration, NFS identification, UDP RPC probes, retries,
and probing arbitrary TCP ports are later extensions.

## Offline verification

`tests/scan/rpc.rs` covers encoding, framing construction, truncated and malformed
replies, XID matching, candidate selection, and validated-response mapping.
In-memory readers exercise fragmented records, short reads, size limits, EOF,
empty fragments, and timeouts. An expired-deadline probe test returns before
opening a connection. `tests/scan/tcp.rs` injects exchanges into the same
collection helper used by the scanner, checking XID propagation, deadline and
limit selection, service mapping, failure preservation, and rejection of
non-candidates or other scan modes.
`tests/model/report.rs` checks the console representation of mapped information.
These are expected fixture outcomes, not measured live RPC findings.

```bash
cargo fmt --all --check
cargo check --offline --locked
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
```

## Reading

- [RFC 5531, section 9](https://www.rfc-editor.org/rfc/rfc5531.html#section-9):
  RPC call/reply fields and accepted-versus-successful procedure results.
- [RFC 5531, section 11](https://www.rfc-editor.org/rfc/rfc5531.html#section-11):
  TCP record markers and fragments.
- [RFC 1833, section 3](https://www.rfc-editor.org/rfc/rfc1833.html#section-3):
  portmapper program, version, and NULL procedure.
- [RFC 4506, section 4.10](https://www.rfc-editor.org/rfc/rfc4506.html#section-4.10):
  length-prefixed opaque data and XDR padding.
- [Tokio I/O tutorial](https://tokio.rs/tokio/tutorial/io): asynchronous reading
  and writing, including why a stream read may return fewer bytes than requested.
