# RPC identification and learning notes

The first RPC goal is identifying a TCP service that successfully answers a
portmapper v2 NULL call. It does not include enumerating registered services,
NFS identification, or RPC over UDP. RPC probing is not active in CLI scans yet.

## What is implemented

- `src/scan/rpc.rs` builds the 40-byte call for program 100000, version 2,
  procedure NULL, using AUTH_NONE. `frame_rpc_record` adds one final-fragment
  TCP record marker.
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

## Where the future network probe connects

After the network exchange returns a complete, reassembled RPC body, its TCP
caller will pass that result and the request XID to `apply_rpc_probe_result`.
The handler validates and maps that body; do not identify a service merely
because reading bytes succeeded. Keep record markers out of the validator input.

There is no placeholder network probe returning fake observations. The result
handler is intentionally not called by `scan_port` until the exchange exists.
Normal TCP scanning still performs its existing passive read on port 111.
HTTP/HTTPS selection, UDP, SYN, CLI syntax, AI behavior, and the package version
are unchanged by these helpers.

## Remaining learning exercises

1. Decode a four-byte TCP record marker: its highest bit marks the final
   fragment, and its lower 31 bits give the payload length excluding the marker.
2. Read complete fragments and assemble one record. Enforce a small total-byte
   limit before allocating or reading each fragment and use one deadline for
   the entire operation, including empty fragments and repeated short reads.
3. Implement the bounded TCP exchange: obtain an XID, send the framed request,
   receive the record, and pass the completed result to the TCP integration
   boundary. Close the initial passive stream before opening a separate probe
   connection to preserve the scanner's descriptor budget.
4. Wire candidate selection into `scan_port`, add stream-level offline tests,
   and perform a separate, authorized controlled-lab validation. Preserve the
   established open-port result if identification fails.

## Offline verification

`tests/scan/rpc.rs` covers encoding, framing construction, truncated and malformed
replies, XID matching, candidate selection, and validated-response mapping.
`tests/scan/tcp.rs` supplies completed fixture exchanges to check identification,
failure preservation, and rejection of non-candidates or other scan modes.
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
