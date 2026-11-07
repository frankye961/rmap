# SMB2 identification and learning notes

Introduced in rmap **0.5.5**.

TCP connect scans automatically negotiate SMB2 on selected, confirmed-open port
445. The initial offer contains dialects 2.0.2 and 2.1. A validated reply supplies
the `smb` label and a protocol-dialect observation; software product, release
version, and OS remain unknown. An open port alone does not identify SMB.

The assistant has not run a live SMB scan. Automated validation uses byte fixtures,
borrowed byte slices, and Tokio in-memory streams.

## Functions and data flow

1. `tcp::scan_port` measures the initial TCP connection and records its state and
   elapsed time. `collect_service` closes that stream before opening a separate
   SMB probe connection, retaining one live socket per task.
2. `tcp::collect_smb` runs only for an open TCP-connect result on port 445. It
   obtains the process-wide client GUID, uses message ID zero for the fresh
   connection, and creates an identification deadline from the configured timeout.
3. `build_smb_negotiate_request` combines `Smb2Header` and `Smb2RequestBody` into
   `Smb2Request`. These types describe field values, not Rust memory to transmit.
4. `encode_smb2_header` and `encode_smb2_request_body` append fields explicitly.
   `encode_smb2_request` combines their bytes without a transport prefix.
5. `frame_smb_message` adds the Direct TCP prefix. `probe` connects, then delegates
   writing and reading to `exchange_smb_stream`. Tests exercise that helper with
   in-memory streams rather than sockets.
6. `read_smb_message` reads one four-byte prefix, validates its zero marker,
   decodes the advertised length, and checks the caller's limit before allocating.
   It reads exactly that payload and returns bytes without the prefix.
7. `response_information` validates the header, negotiation body, and buffer
   bounds before mapping service information. `apply_service_probe_result`
   supplies the existing report model or appends an identification diagnostic.

The normal report shows the service and dialect observation. Optional AI context
includes these structured fields when the result falls within its existing
eight-observation limit. No AI request is required for deterministic identification.

## Wire layout

The initial request has a 64-byte SMB2 header, a 36-byte fixed body, and two
two-byte dialect entries: **104 bytes**, or **108 bytes** with Direct TCP framing.

| Encoding | Meaning |
| --- | --- |
| `FE 53 4D 42` | Four literal protocol-identifier bytes |
| Little-endian numeric fields | SMB2 header, body, and dialect values |
| Unchanged byte arrays | Client GUID and signature fields |
| Zero byte plus three big-endian length bytes | Direct TCP prefix, excluding itself from the length |

The request body's `StructureSize` remains 36 even though the dialect entries
increase the encoded body length. Likewise, a successful response's body
`StructureSize` is 65, while its fixed fields occupy 64 bytes. The minimum complete
fixed successful response therefore occupies **128 bytes**, including its header.

Selected response offsets are relative to the unframed SMB2 header:

| Bytes | Field | Check |
| --- | --- | --- |
| `0..4` | Protocol identifier | Matches the SMB2 identifier |
| `4..6` | Header structure size | 64 |
| `8..12` | Status | Success before parsing a successful negotiation body |
| `12..14` | Command | NEGOTIATE |
| `16..20` | Flags | Server response; synchronous format |
| `20..24` | Next command | Zero for this single-message exchange |
| `24..32` | Message ID | Matches the request |
| `64..66` | Body structure size | 65 |
| `68..70` | Selected dialect | One of the two offered dialects |
| `120..124` | Security-buffer offset and length | Nonempty range follows fixed fields and fits within the reply |

An empty security buffer does not require dereferencing its offset. Buffer-range
checks do not authenticate the server or interpret authentication tokens.

## Rust and I/O concepts

- `Vec<u8>` owns encoded bytes. Borrowing a model with `&` lets encoding read its
  fields without consuming it. `extend_from_slice` appends bytes in protocol order.
- `to_le_bytes` controls integer byte order explicitly; Direct TCP framing uses
  network byte order instead. Rust struct padding is never sent.
- `write_all` continues across short writes. Its successful result means the
  request was written to the stream; response bytes come from reading afterward.
- `read_exact` fills the supplied buffer across short reads. The received bytes
  remain in that buffer, rather than being returned by the method.
- `timeout_at(...).await` wraps an I/O result in a timeout result. The two
  `map_err(...)?` operations distinguish timeout from connection/read/write failure.
- One absolute deadline covers the identification exchange. Explicit expiration
  checks reject stale deadlines even if an operation could complete immediately.
- `OnceLock` initializes the client GUID once per process. The existing
  `getrandom` dependency supplies its bytes; initialization failure becomes a
  diagnostic rather than a guessed service identity.

The production collector limits assembled replies to **4096 bytes**, independently
of the transport's larger 24-bit wire-length limit. The initial connection has
its own timeout budget; console elapsed time records that connection measurement,
not the subsequent identification exchange.

## Evidence, scope, and validation

Probe failures preserve the measured open state, initial connection time, earlier
identification, and existing banner bytes. Successful negotiation records protocol
evidence; it does not establish authentication, share access, vulnerabilities, or
exploitability. Complete SMB packets are not exported or stored historically.

Only TCP connect mode on selected port 445 enters this path. UDP and SYN scans
do not perform SMB negotiation. Port 139, SMB1, SMB3 negotiation, authentication,
share enumeration, server software identification, and OS detection are later work.
Failure to negotiate the offered dialects does not prove that a server lacks SMB.

`tests/scan/smb.rs` covers independent wire fixtures, length boundaries, fragmented
reads, EOF, timeout/error paths, response validation, and in-memory exchanges.
`tests/scan/tcp.rs` checks candidate scope and preservation of results on success
and failure. Report and AI-context tests check the downstream structured fields.
These tests establish fixture behavior, not live interoperability or scan accuracy.

For a controlled lab experiment, compare a known SMB 2.0.2/2.1 listener, a
listener requiring other dialects, a silent listener, malformed responses, and a
closed port. Retain the code revision, exact command, service configuration,
effective scan settings, stdout/stderr, and packet capture. Check request and reply
message IDs and framing lengths. Record expected and measured results separately.
See [the research guide](research.md) for the reproducibility checklist.

An example command for an authorized lab host is:

```bash
rmap --tcp --target 192.0.2.10 --ports 445 --timeout-ms 1000
```

This example has not been run during offline validation.

## Primary sources

- [Microsoft: synchronous SMB2 header](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4).
- [Microsoft: NEGOTIATE request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5).
- [Microsoft: NEGOTIATE response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5).
- [Microsoft: Direct TCP transport](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83).
- [Microsoft: SMB2-only negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/77f696b8-9aa0-4ed1-abb2-c097c0ccb05a).
- [Tokio I/O tutorial](https://tokio.rs/tokio/tutorial/io).
- [Tokio: write_all](https://docs.rs/tokio/latest/tokio/io/trait.AsyncWriteExt.html#method.write_all) and [read_exact](https://docs.rs/tokio/latest/tokio/io/trait.AsyncReadExt.html#method.read_exact).
- [Tokio: timeout_at](https://docs.rs/tokio/latest/tokio/time/fn.timeout_at.html).
- [Rust: OnceLock](https://doc.rust-lang.org/std/sync/struct.OnceLock.html).
