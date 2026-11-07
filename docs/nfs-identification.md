# NFSv3 identification and learning notes

Available in rmap **0.5.4**.

The initial NFS feature identifies a service answering an NFSv3 NULL request
on selected, confirmed-open TCP port 2049. The reply supplies protocol evidence;
it does not identify server software or establish permission to access files.
Automated validation uses offline fixtures and in-memory streams. The assistant
has not performed a live NFS scan or filesystem operation.

## Request fields

The request uses the same 40-byte argument-free RPC header as portmapper, with
different program and program-version values:

| Field | Value | Meaning |
| --- | --- | --- |
| Message type | 0 | CALL |
| RPC protocol version | 2 | RPC envelope version |
| Program | 100003 | NFS |
| Program version | 3 | NFSv3 |
| Procedure | 0 | NULL |
| Credential and verifier | AUTH_NONE, empty bodies | No authentication data supplied |

Each integer occupies four bytes in big-endian order. The XID occupies another
field and matches the response to the particular request. The two version
fields have different meanings: RPC version 2 carries the NFS version 3 request.
Neither value is a daemon's software release version.

## Functions and flow

1. `tcp::scan_port` first measures a normal TCP connection. Its success establishes
   the open-port result. `tcp::collect_service` selects identification. If port
   2049 was selected, the initial stream closes
   before the NFS probe connection opens, preserving one live socket per task.
2. `nfs::is_nfs_candidate` chooses port 2049 as the initial hint. It does not
   identify NFS by itself. Other selected ports continue through their existing
   identification paths; advertised RPC registrations never expand scan scope.
3. `tcp::collect_nfs` reuses `run_rpc_exchange` to generate an XID, calculate one
   absolute identification deadline, and enforce the 4096-byte reply bound.
4. `nfs::build_nfs_null_call` delegates request encoding to `rpc::build_rpc_call`.
   It returns the unframed bytes; it does not open a socket.
5. `nfs::probe` passes the target, request, deadline, and limit to
   `rpc::exchange_rpc_call`. That helper adds TCP framing, connects, sends the
   complete request, and reassembles the reply under the same deadline.
6. `nfs::response_information` validates the XID, REPLY, MSG_ACCEPTED, verifier,
   and procedure SUCCESS using `rpc::validate_rpc_success_reply`. The returned
   cursor must equal the reply length because NULL has no result payload.
7. `apply_service_probe_result` applies mapped service information or appends a
   diagnostic. The mapper stores `nfs` and
   `RPC program 100003; NFS protocol version 3; NULL procedure succeeded`.
   Software product and version stay unknown.

The initial connection and identification have separate timeout budgets. Within
the NFS exchange, connecting, writing, and reading share one absolute deadline.
The console's elapsed measurement remains the initial TCP connection time.
Probe failures preserve port state, elapsed time, earlier raw banner bytes,
and earlier identification. Errors such as RPC program-version mismatch remain
identification failures; they do not become a guessed NFS version.

## Rust concepts used here

- `Vec<u8>` owns the request bytes. Passing `&_unframed_request` borrows them
  as a byte slice for the shared exchange; ownership stays in the NFS function.
- `async`/`.await` allow I/O to yield to the existing Tokio scheduler.
- `build_nfs_null_call` returns a `Vec<u8>` directly because constructing this
  fixed request has no recoverable error path. `?` propagates errors from the
  exchange and reply validation.
- The successful reply validator returns a `usize` cursor, not reply bytes.
  Compare that number directly with `_reply.len()`; a number has no `.len()`.
- The cursor comes after a potentially padded verifier. Its correct value need
  not be 24, so validation uses the returned position instead of a fixed length.
- The existing mapper constructs `ServiceInformation`, keeping parsed protocol
  evidence separate from the measured `ScanResult` state.

Completed functions retain responsibility comments; implementation exercise
instructions have been removed from their bodies.

## Scope and verification

This implementation supports NFSv3 over TCP port 2049. NFSv2/v4 negotiation,
nonstandard-port discovery, UDP NFS, export enumeration, mounts, file access,
and OS detection remain later work. A successful NULL response does not establish
export availability, authorization, vulnerability, or exploitability.

Portmapper DUMP may advertise NFS registrations. Those entries remain reported
advertisements; the NFS probe is an independent check performed only if the
corresponding candidate port was already selected. Port 111 is not required.

`tests/scan/nfs.rs` covers request encoding, XIDs, empty and padded verifier
replies, malformed responses, unexpected payload, candidate selection, and an
expired deadline that returns before connecting. `tests/scan/tcp.rs` injects
completed exchanges to verify bounds, scope, result preservation, and reporting
data. These are fixture outcomes, not measured findings from a live NFS server.

For a later authorized lab test, retain the code revision, CLI command, service
configuration, output, and packet capture. Check a known NFSv3 service, a listening
non-NFS service, and a service that rejects the requested version. Compare
expected conditions with observed results without treating every failure as
proof that NFS is absent.

## Primary reading

- [RFC 1813, section 2](https://www.rfc-editor.org/rfc/rfc1813.html#section-2):
  NFSv3 RPC information.
- [RFC 1813, section 3.3.0](https://www.rfc-editor.org/rfc/rfc1813.html#section-3.3.0):
  the NULL procedure and its argument-free request and result.
- [RFC 5531, section 9](https://www.rfc-editor.org/rfc/rfc5531.html#section-9):
  request/reply envelopes and successful versus denied procedures.
- [Tokio I/O tutorial](https://tokio.rs/tokio/tutorial/io):
  asynchronous streams, reads, writes, and short I/O operations.
