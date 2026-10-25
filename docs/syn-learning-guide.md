# Learning Rust and networking through rmap's SYN scanner

This guide explains the concepts and functions used while building the SYN
scanner in [src/scan/syn/](../src/scan/syn/mod.rs). Read it alongside those modules.
Examples describe the current implementation; they are not instructions to run
a live scan.

The focus is the SYN work we have completed together: Rust syntax, ownership,
socket setup, packet construction, checksums, asynchronous sending, receiving,
and the beginning of reply parsing.
The earlier TCP scanner and banner grabbing are explained briefly for context.

## Contents

1. [Current state and overall flow](#1-current-state-and-overall-flow)
2. [Networking vocabulary](#2-networking-vocabulary)
3. [Rust syntax and types](#3-rust-syntax-and-types)
4. [Ownership and socket lifetime](#4-ownership-and-socket-lifetime)
5. [Addresses and the three sockets](#5-addresses-and-the-three-sockets)
6. [TCP header bytes](#6-tcp-header-bytes)
7. [The Internet checksum](#7-the-internet-checksum)
8. [Tokio and readiness](#8-tokio-and-readiness)
9. [Timeouts and deadlines](#9-timeouts-and-deadlines)
10. [Receiving initialized bytes safely](#10-receiving-initialized-bytes-safely)
11. [Every function in the SYN module](#11-every-function-in-the-syn-module)
12. [Library functions and methods](#12-library-functions-and-methods)
13. [Tests and development commands](#13-tests-and-development-commands)
14. [What remains unfinished](#14-what-remains-unfinished)
15. [Reading list](#15-reading-list)
16. [Learning to parse packet bytes](#16-learning-to-parse-packet-bytes)

## 1. Current state and overall flow

Version 0.5.0 connects the basic IPv4 SYN pipeline end to end: build and send a
SYN, receive packets, validate and match replies, classify them, attempt bounded
reset cleanup, and report measurements. Invalid or unrelated packets are ignored
under the original deadline. Silence is tentatively filtered; local failures
are unknown. Cleanup failure preserves an open result.

The former large `syn.rs` is split by responsibility:

| File | Responsibility |
| --- | --- |
| [mod.rs](../src/scan/syn/mod.rs) | Prepare and own resources, send, and orchestrate cleanup. |
| [packet.rs](../src/scan/syn/packet.rs) | Pure header construction, parsing, and checksums. |
| [reply.rs](../src/scan/syn/reply.rs) | Match, classify, handle receive outcomes, preserve measurements. |
| [socket.rs](../src/scan/syn/socket.rs) | Source selection, socket setup, shared readiness, and I/O. |

Tests include parser fixtures, endpoint matching, invalid traffic, deadlines, and
cleanup failure. They use synthetic packets and local Unix resources rather than
raw network scans.

Passing tests and compilation do not establish that the full SYN scanner works
on a real network. We have not validated this path with a live scan.

```text
CLI selects --syn
    |
scan/mod.rs dispatches to syn::scan_port
    |
Validate destination IPv4 address
    |
Discover local source IP
    |
Reserve local TCP source port
    |
Generate random sequence number
    |
Build 20-byte TCP SYN header and checksum
    |
Create nonblocking raw TCP socket
    |
Register socket with Tokio
    |
Create one deadline
    |
Send SYN -> receive raw IPv4 packets until deadline
    |
Parse -> match -> classify
    |       |
    |       +-- invalid/unrelated -> receive again, same deadline
    |
Open -> bounded RST cleanup; closed -> no cleanup
    |
Map measured status and diagnostics -> console report
```

The normal TCP connect scanner uses the operating system's TCP connection API.
The SYN path constructs a TCP header itself. These are separate implementations.
Service probing and AI interpretation belong after measured port discovery.

## 2. Networking vocabulary

| Term | Meaning here |
| --- | --- |
| Host | A machine or network endpoint identified by an IP address. |
| IPv4 address | A 32-bit address, commonly written as four decimal numbers. |
| Port | A 16-bit transport-layer endpoint number. TCP and UDP have separate port spaces. |
| Source | The local side sending this probe. |
| Destination | The remote side being probed. |
| Socket | An operating-system communication resource owned by the application. |
| Socket address | An IP address together with a port. |
| File descriptor | A process-local integer identifying an open OS resource on Unix. |
| TCP segment | A TCP header plus any TCP payload. |
| IPv4 packet | An IPv4 header and its payload; here the payload is a TCP segment. |
| Header | Structured metadata before the application payload. |
| Payload | The data carried after a protocol's header. Our SYN has no TCP payload. |
| SYN | TCP flag used when starting connection establishment. |
| ACK | TCP flag indicating that the acknowledgment field is meaningful. |
| RST | TCP flag used to reset or reject a connection. |
| Banner | Application data such as an SSH greeting, not a TCP SYN/ACK packet. |

A normal TCP handshake is SYN, SYN/ACK, ACK. A SYN scan aims to infer the port
state without completing that handshake. Nmap's
[SYN scan diagrams](https://nmap.org/book/synscan.html) illustrate the exchanges.

An open port does not identify its application or prove a vulnerability. A
timeout only tells us that the expected operation did not finish in time.

## 3. Rust syntax and types

### Integers, arrays, slices, and vectors

| Rust type | Meaning in this code |
| --- | --- |
| `u8` | Unsigned 8-bit integer: one byte. |
| `u16` | Unsigned 16-bit integer: ports, window, checksum. |
| `u32` | Unsigned 32-bit integer: sequence numbers and checksum accumulator. |
| `usize` | Integer used for indexes and lengths; returned byte counts use it. |
| `[u8; 20]` | An array containing exactly 20 bytes. |
| `[0; 20]` | An expression creating 20 zero bytes. |
| `&[u8]` | A borrowed view of a sequence of bytes. |
| `&mut [u8; 20]` | Exclusive mutable access to a 20-byte array. |
| `Vec<u8>` | An owned, dynamically sized collection of bytes. |

`buffer[received]` selects one element at that index. `buffer[..received]`
selects the prefix starting at zero and ending before `received`. If 40 bytes
arrive, their indexes are 0 through 39; index 40 is outside the received prefix.

`0..2` includes indexes 0 and 1. All range ends used for header slices are
exclusive. `&header` borrows bytes without transferring ownership.

### Names, modules, and calls

- `use` brings a name into scope; it does not add a Cargo dependency.
- `crate::model` starts at this crate's module root.
- `pub(super)` exposes an item to its parent module, rather than making it public
  to every external user.
- `Socket::new(...)` calls an associated function using `::`.
- `socket.bind(...)` calls a method on an existing value using `.`.
- `//!` documents a module; `///` documents the following item.

Names are case-sensitive: `Ok` exists; `OK` is a different name. Functions
conventionally use `snake_case`.

A leading underscore, as in `_socket`, does not change the value or prevent its
use. It suppresses unused-variable warnings. We currently retain those names in
some helpers as a naming preference. `_` alone is a discard pattern, not a name
that can be used later.

### Tuples and destructuring

`(socket, port)` is one tuple value containing two values. Therefore:

```rust
Ok((socket, port))
```

passes one tuple to `Ok`. `Ok(socket, port)` incorrectly passes two arguments.

This binding extracts the tuple members:

```rust
let (_source_socket, source_port) = result;
```

It creates two names. Merely writing those names on the right of an expression
does not define them.

### Result, Option, and match

`Result<T, E>` means either `Ok(T)` or `Err(E)`. `std::io::Result<T>` is shorthand
for `Result<T, std::io::Error>`.

`Option<T>` means either `Some(T)` or `None`. For example, socket2's `as_socket()`
returns an option because not every OS socket address represents an IP address.
`ok_or(...)` turns `Some(value)` into `Ok(value)` and `None` into an error.

`IpAddr` is an enum with IPv4 and IPv6 variants. Matching `IpAddr::V4(ip)` extracts
an `Ipv4Addr`. Calling `IpAddr::V4(...)` in an expression constructs a variant;
it is not a boolean test.

A `match` examines a value and selects an arm. The pattern is before `=>`;
the expression or block to execute is after it:

```rust
let value = match result {
    Ok(value) => value,
    Err(error) => return Err(error),
};
```

Names extracted by an arm only exist within that arm. Arms that finish normally
must yield compatible types. An arm that returns from the function does not
need to produce the successful arm's value.

### When to use `?`, `;`, or both

For a `Result`, `?` extracts the success value or returns the error from the
enclosing function, converting the error when a suitable conversion exists.
It does not log the error, retry, or make an operation asynchronous.

The enclosing function must support that propagation. Our I/O helpers return
`Result` and use `?`. `scan_port` returns a `ScanResult`, so it uses explicit
matches and converts failures into measured-result records.

| Expression | Explanation |
| --- | --- |
| `let port = addr.port();` | Obtain an infallible value and finish the statement. |
| `let addr = socket.local_addr()?;` | Propagate failure, extract the address, finish the statement. |
| `socket.bind(&addr)?;` | Propagate failure; on success continue after the statement. |
| `Ok((socket, port))` | Final expression returned by the block; no semicolon. |
| `return Ok(());` | Explicitly exit the function successfully. |

`()` is the unit value: no additional data. `Result<(), E>` can succeed without
returning useful data, or fail with an error.

A semicolon normally makes an expression into a statement whose value is
discarded. Ending a function with `Ok(value);` leaves its body with `()` instead
of returning the result. Newlines do not finish Rust statements.

`?` also works with `Option` in an appropriate function returning `Option`, but
does not automatically convert between `Option` and `Result`.

### Formatting, closures, and iterators

`format!("Failed: {error}")` creates a `String` containing an inserted value.
For fixed text, `"message".into()` can convert a string literal into the expected
`String`. `map_err` transforms an error; it does not handle or propagate it by
itself.

`|registered_socket| { ... }` is a closure: a small anonymous function passed to
another function. It borrows `_header` and the destination address from the
surrounding scope. The `try_io` closure performs an immediate OS operation; it
does not contain `.await`.

`.iter()` visits borrowed elements; `.map(...)` transforms them; `.collect()`
gathers the transformed elements into a collection. The receive function's
return type lets Rust infer `Vec<u8>` for its collected bytes.

`Box<dyn std::error::Error>` holds an owned error of different possible concrete
types behind a common interface. An earlier port-allocation exercise used it
while parsing an address string. The refactored helper constructs the address
directly and returns the simpler `std::io::Result` instead.

See the [Rust Book on Result](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html)
and [closures](https://doc.rust-lang.org/book/ch13-01-closures.html) for fuller examples.

## 4. Ownership and socket lifetime

A Rust socket value owns an OS resource. When the owner is dropped, that resource
is closed. Returning only an assigned port number would drop the helper's socket
and release the reservation immediately.

`create_unconnected_tcp_socket` returns both the socket and port. `scan_port`
retains `_source_socket` until the function exits. This keeps that socket bound
while sending and receiving. Do not replace this binding with a discard `_`.

Registration moves `raw_tcp` into `AsyncFd`. After that, access the socket through
the wrapper. `get_ref()` borrows the underlying socket; it does not transfer it.
Dropping the wrapper unregisters and closes its owned socket.

Borrowing with `&reg_tcp_raw` lets the send and receive helpers use the same
socket without taking ownership. Their completion does not close it.

## 5. Addresses and the three sockets

The current SYN path creates three socket resources for different reasons:

| Socket | Purpose | Important limitation |
| --- | --- | --- |
| Temporary UDP socket | Discover the local IP selected for the target route. | Its UDP port does not reserve a TCP port. |
| Unconnected TCP socket | Bind an available local TCP source port. | It does not send our manually built SYN. |
| Raw TCP socket | Send TCP bytes and receive raw IPv4 TCP packets. | It does not provide TCP connection management or reply matching. |

### Source-IP discovery

`discover_source_ip(target)` binds a UDP socket to `0.0.0.0:0`, associates it with the
destination, and reads `local_addr().ip()`.

Here UDP `connect` selects a peer and a route; it does not perform a TCP handshake
or send an application datagram. There is no `send` in this helper. The eventual
probe is still TCP. Systems with protocol-dependent policy routing may need more
precise source-selection logic later.

### Binding versus connecting

- `bind` chooses a local endpoint.
- TCP `connect` starts a normal connection and handshake.
- UDP `connect` sets a default peer for a connectionless socket.
- `local_addr` reads the socket's local endpoint.

Local port `0` requests automatic allocation when binding the TCP reservation
socket. It does not request an automatically chosen remote service port.

`0.0.0.0` is the IPv4 unspecified local address, not a discovered source address.
`target.ip()` and `target.port()` describe the remote endpoint.

### Socket configuration

`Domain::IPV4` selects IPv4. `Type::STREAM` with `Protocol::TCP` creates a normal
TCP socket; `Type::RAW` with that protocol selects the raw TCP interface.
socket2 0.5 exposes `Type::RAW` through its `all` Cargo feature.

`SocketAddr::from((ip, port))` creates a standard IP endpoint from one tuple.
`SockAddr::from(address)` adapts it to socket2's OS address representation.

In this Linux raw-socket path, the real TCP destination port lives in the TCP
header. The address passed to raw `send_to` uses port zero. Local raw binding also
uses zero; it is the separate stream socket that reserves the TCP source port.

Linux supplies the outgoing IPv4 header because we do not enable `IP_HDRINCL`.
Raw reception includes the IPv4 header. Raw TCP packets also reach the kernel's
TCP handler: a raw socket does not disable the normal TCP stack. Kernel-generated
RSTs must be considered when implementing cleanup. Creating the raw socket
requires `CAP_NET_RAW` in the governing namespace. Details are in
[Linux raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html).

## 6. TCP header bytes

The current builder creates exactly 20 bytes: a minimum TCP header without
options or payload. This is not a complete Ethernet frame or an IPv4 header.

| Byte indexes | Field | Current value or source |
| --- | --- | --- |
| 0–1 | Source port | Reserved local TCP port. |
| 2–3 | Destination port | `target.port()`. |
| 4–7 | Sequence number | Random `u32`. |
| 8–11 | Acknowledgment number | Zero for this initial SYN. |
| 12 | Data offset and reserved bits | `0x50`: five 32-bit words, or 20 bytes. |
| 13 | Flags | `0x02`: SYN. |
| 14–15 | Receive window | 1024, chosen for this exercise. |
| 16–17 | Checksum | Computed after filling the other fields. |
| 18–19 | Urgent pointer | Zero. |

The window is an advertised TCP receive-window value, not the scan timeout,
concurrency, packet length, or receive-buffer allocation.

Network byte order is big-endian: the most significant byte comes first.
`80u16.to_be_bytes()` yields `[0, 80]`; `40000u16.to_be_bytes()` yields
`[0x9c, 0x40]`. `from_be_bytes` performs the reverse conversion.

Hexadecimal `0x02` is decimal 2. `0x50` is binary `0101_0000`; its high nibble
holds data offset 5. A nibble is four bits. The builder's offset must be multiplied
by four to obtain bytes.

Sequence numbers identify positions in TCP's byte sequence space. A SYN consumes
one sequence number even without payload. Later reply matching will validate an
appropriate acknowledgment, using wrapping arithmetic for the 32-bit sequence
space. Generating a random probe value is not an implementation of a complete
TCP stack's initial-sequence-number algorithm.

For field definitions, consult [RFC 9293, section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1).

## 7. The Internet checksum

The checksum detects many accidental changes; it does not authenticate the peer
or provide cryptographic integrity.

Our calculation combines a 12-byte IPv4 pseudo-header with the 20-byte TCP header:

| Pseudo-header bytes | Contents |
| --- | --- |
| 0–3 | Source IPv4 address. |
| 4–7 | Destination IPv4 address. |
| 8 | Zero. |
| 9 | Protocol number 6, meaning TCP. |
| 10–11 | TCP segment length, here 20, in big-endian order. |

The pseudo-header is calculation input. We do not prepend it to the transmitted
TCP header. Its addresses help detect misdelivery. A future TCP segment with
payload must include that payload in the TCP length and checksum input.

### Calculation, in order

1. Set the TCP checksum field to zero.
2. Read pairs of input bytes as big-endian 16-bit words.
3. Add each word to the accumulator.
4. Fold carry bits into the low 16 bits after each addition.
5. If a final byte remains, use it as the high byte of a word padded with zero.
6. Fold any remaining carry, then invert the final 16 bits.
7. Write the result into TCP bytes 16–17 in big-endian order.

The odd-byte padding is for calculation only; no extra byte is transmitted.

### Why carry folding fixes overflow

The expression is:

```rust
sum = (sum & 0xFFFF) + (sum >> 16);
```

`& 0xFFFF` retains the lower 16 bits. `>> 16` extracts the carry. Adding them
implements end-around carry. For example, `0xFFFF + 1` produces `0x10000`,
which folds to `0x0000 + 1`, or `0x0001`.

Originally, repeated `wrapping_add` operations discarded overflow beyond 32 bits
before final folding. Once discarded, those carry bits cannot be recovered.
Folding after every word bounds the accumulator for arbitrarily long input.

The final odd-byte addition still uses `wrapping_add` in the current code, but
cannot overflow `u32` because the accumulated sum is already bounded and only
one padded word remains. The final loop folds its carry.

`!(sum as u16)` truncates to the folded width, then flips its bits. `!` is bitwise
inversion for integers, logical negation for booleans; it does not test an enum.

For verification, calculating the checksum over a correct pseudo-header and TCP
segment including its stored checksum yields zero with our complemented function.
That check detects many changes, not every possible corruption or forgery.

Read [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071.html) alongside
`internet_checksum`; it explains one's-complement addition and checksum properties.

## 8. Tokio and readiness

`async fn` returns a future. `.await` allows a pending operation to yield control
to the runtime so another task can run. Writing `async` does not make a blocking
OS call nonblocking, nor create a dedicated thread.

The scanner uses a Tokio runtime with I/O and time enabled. `AsyncFd` registration
happens inside that runtime. Its Unix implementation fits the current Linux
raw-socket design; it is not a portable Windows backend.

### Nonblocking sockets

`set_nonblocking(true)` makes a socket operation return `WouldBlock` when it
cannot proceed immediately. This is a temporary readiness condition, not evidence
that a remote port is closed.

An unconditional retry loop could consume CPU. `AsyncFd` lets the task wait for
OS readiness notifications instead. The socket must remain nonblocking.

### Registration and its unsafe contract

In the project's installed Tokio API, `AsyncFd::register(raw_tcp)` is unsafe,
and the older `AsyncFd::new` is deprecated. The contract requires the underlying
descriptor to remain valid, open, and unchanged while registered. Owning the
`Socket` inside the wrapper and not manually closing or replacing its descriptor
is how this code maintains that requirement.

`unsafe` does not validate that contract; the programmer must establish it.
The safety comment records the reason. Read the API for the version in your
lockfile, because older examples may show a different registration method.

### Readiness is a hint

`writable().await` yields a readiness guard for sending. `readable().await` yields
one for receiving. Neither guarantees the next operation succeeds: readiness
can become stale.

The guard's `try_io` runs a closure containing one nonblocking operation. If
that operation reports `WouldBlock`, it clears the stale readiness indication.
The next wait can then sleep until another notification.

For our send closure, the result is shaped like:

```text
Result<Result<usize, std::io::Error>, TryIoError>
```

| Pattern | Meaning | Action |
| --- | --- | --- |
| `Ok(Ok(count))` | The OS operation succeeded. | Validate or use the byte count. |
| `Ok(Err(error))` | The OS operation failed with another I/O error. | Retry Interrupted; otherwise return the error. |
| `Err(_)` | The operation would block. | Continue to another readiness wait. |

The outer result concerns readiness handling. The inner result is the actual
socket operation. `Err(Err(error))` is not a valid pattern for this shape.

Do not clear readiness merely because an operation succeeded. Do not ignore a
successful send result and continue the loop: that could repeatedly transmit SYNs.

The current `Interrupted` retries retry a system call that did not complete;
they are not a network retransmission policy for unanswered probes.

Read [AsyncFd](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html)
and [the guard's try_io method](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFdReadyGuard.html#method.try_io).

## 9. Timeouts and deadlines

`Duration` is a length of time. An `Instant` is a monotonic time point.
`std::time::Instant` measures elapsed time for reports; `tokio::time::Instant`
is used for async timer deadlines.

The current deadline is created after socket setup and registration:

```rust
let deadline = tokio::time::Instant::now() + timeout;
```

The same value is passed to sending and receiving. It bounds their combined
waiting and retry work. It does not currently bound the earlier setup work.
Reported elapsed time starts before setup, so it can exceed the requested timeout.

Recalculating `now() + timeout` on each retry would extend the operation's allowed
time. Later, ignoring unrelated packets must also preserve the original deadline.

### Why `??` appears

`timeout_at(deadline, socket.readable()).await` produces two results:

```text
Result<io::Result<ReadinessGuard>, Elapsed>
```

`map_err` converts the outer expiration error to an I/O `TimedOut` error.
The first `?` handles expiration; the second handles the inner readiness failure.
This is two ordinary `?` operators, not a separate special operator.

`timeout_at` may accept an immediately ready future even after the deadline.
Explicit checks before and after readiness waiting prevent starting an I/O
attempt when our code observes the deadline has passed. This is cooperative
deadline handling, not a hard real-time guarantee about exact OS completion time.

See [Tokio timeout_at](https://docs.rs/tokio/latest/tokio/time/fn.timeout_at.html).

## 10. Receiving initialized bytes safely

socket2's `recv` accepts a mutable slice of `MaybeUninit<u8>`. This represents
storage whose bytes may not yet hold initialized Rust values.

The current receive buffer has capacity 65,535 bytes, covering the maximum IPv4
packet size. Its capacity is not the amount of data received.

After `recv` returns `Ok(received)`, only the prefix `buffer[..received]` is
guaranteed initialized by that call. The code visits those elements, reads each
with `assume_init`, and collects them into an owned `Vec<u8>`.

Calling `assume_init` is unsafe because reading uninitialized memory is invalid.
Here its justification is that successful `recv` initialized the returned prefix.
Never use the whole buffer's capacity as the initialized length. On failure,
do not make assumptions about newly received bytes.

The resulting vector can safely outlive the local receive buffer. Returning a
borrowed slice of that local buffer would not be valid. The data is binary:
TCP/IP headers must be parsed as bytes, not converted to UTF-8 text.

Each successful raw `recv` obtains a packet, unlike application TCP stream reads,
which may split or combine data independently of application messages. Future
packet parsing must still validate lengths, header fields, and fragmentation.

This local array occupies roughly 64 KiB in each pending receive future. That
matters when many probes run concurrently; current code has not been optimized
or load-tested for raw socket count and receive-buffer memory usage.

Read [MaybeUninit](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html)
and [socket2 recv](https://docs.rs/socket2/0.5.10/socket2/struct.Socket.html#method.recv).

## 11. Every function in the SYN module

The names are better navigation anchors than line numbers, which change after edits.

### `scan_port`

Input: a destination `SocketAddr` and timeout. Output: a `ScanResult`.
It calls `prepare_probe`, retains its resource owner, creates the deadline, sends
the SYN, and delegates replies to `finish_syn_probe`. Setup and send errors
return `Unknown` with the actual message and elapsed time.

### `prepare_probe`

Validates IPv4, discovers the source IP, reserves a TCP source port, generates
the sequence, builds the SYN, and prepares/registers the raw socket. It returns
a private `PreparedProbe` owning the reservation, probe data, header, and
registered socket. The reservation remains alive across asynchronous operations.
Setup sends no SYN packet.

### `finish_syn_probe`

Calls `wait_for_syn_reply`, maps receive errors, measures response elapsed time,
and invokes cleanup only for open results. Cleanup warnings become observation
text; they do not change the state. Result construction uses the shared mapper.

Receive/cleanup callbacks keep the flow testable without raw privileges. Real
callbacks call socket helpers; tests supply packet queues, pending futures, or
I/O errors. `FnMut` lets a callback advance its queue; the returned future is
awaited by the same orchestration. This is a small test seam, not a provider framework.

### `wait_for_syn_reply`

Receives under one deadline and calls `interpret_syn_reply`. Malformed or unrelated
traffic causes another receive rather than deciding the port state. It yields
between discarded packets so busy raw sockets do not monopolize the runtime.

### `interpret_syn_reply`

Calls the IPv4 parser, TCP parser, matcher, and classifier in order. A parser
error denotes malformed/unsupported input; `Ok(None)` denotes no accepted matching
reply; `Ok(Some((status, reply)))` supplies the measurement and reply for cleanup.

### `receive_failure`

Maps receive expiration to tentative `Filtered`, explicitly noting uncertainty.
Other local receive failures become `Unknown`, preserving the actual error.

### `cleanup_diagnostic`

Caps cleanup at 100 ms of the remaining probe time. Errors become an optional
warning string rather than overwriting measured status. Closed results skip it.

### `generate_sequence_number`

Calls `getrandom::u32()` to obtain randomness from an OS source. Its error is
propagated to the caller; no fixed fallback is silently substituted. The sequence
is retained for eventual reply matching. See [getrandom u32](https://docs.rs/getrandom/0.4.3/getrandom/fn.u32.html).

### `unknown_result`

Builds a TCP `ScanResult` with `PortStatus::Unknown`, supplied elapsed time and error,
and no service, banner, observation, or service information. It avoids repeated
struct literals and does not invent a remote state from a local failure.

### `port_to_bytes`

Converts a `u16` into its two big-endian bytes. The exercise returns
`Result<[u8; 2], String>`, although this conversion itself cannot currently fail.

### `empty_tcp_header`

Returns a zero-filled `[u8; 20]`. This is an exercise helper; the current builder
allocates `[0; 20]` directly, so it does not call this helper.

### `write_ports`

Mutates bytes 0–1 and 2–3 using `port_to_bytes` and `copy_from_slice`.
The other bytes remain unchanged. The caller keeps ownership of the header.

### `write_syn_fields`

Writes sequence number, zero acknowledgment, data offset, SYN flag, window, and
zero urgent pointer at their defined offsets. It leaves ports and checksum intact.
Use this before computing the checksum, because changing these bytes afterward
would invalidate the checksum.

### `internet_checksum`

Accepts an arbitrary borrowed byte slice. It pairs bytes, folds one's-complement
carries, handles an odd final byte, and returns the complemented 16-bit sum.
The current `Result` interface is retained from the exercises; there is no
explicit failure branch in this implementation.

### `ipv4_pseudo_header`

Uses IPv4 `octets()` and the TCP length to construct the 12-byte checksum-only
prefix. It does not build a real IPv4 packet header.

### `apply_tcp_checksum`

Zeroes the existing checksum, constructs the pseudo-header for a 20-byte segment,
concatenates both calculation inputs in a vector, computes the checksum, and
writes it back. Replacing an old checksum works because it is zeroed first.
This helper is specific to our no-payload, fixed-length TCP header.

### `build_syn_header`

Creates the array, then calls `write_ports`, `write_syn_fields`, and
`apply_tcp_checksum` in order. It returns ownership of the array. This function
does not open sockets or send packets, so it is straightforward to unit-test.

### `discover_source_ip`

This is the UDP-based source-IP discovery helper, formerly named `connect`.
It binds a temporary UDP socket, associates the IPv4 destination, and returns the
local IPv4 address. Its socket is dropped on return. It does not create a TCP
connection or send the SYN itself.

### `create_unconnected_tcp_socket`

Creates a stream/TCP socket, builds a local source-IP/port-zero address, binds,
reads `local_addr`, converts `SockAddr` using `as_socket`, extracts the port,
and returns `(Socket, u16)`. It neither connects nor listens. Returning the
socket lets the caller retain the reservation.

### `prepare_raw_tcp_socket`

Creates an IPv4 raw TCP socket, binds the source IP with port zero, enables
nonblocking mode, and returns the owned socket. Setup failures propagate as
I/O errors. It does not register with Tokio; `prepare_probe` does that afterward.

### `register_raw_socket`

Moves the socket into `AsyncFd`, documenting the unsafe descriptor-lifetime
contract beside the call. It returns descriptive registration errors.

### `wait_ready`

Shares deadline checks and `timeout_at` handling for both sending and receiving.
It checks time before and after awaiting `socket.ready(interest)`. The sender
requests writable interest; the receiver requests readable interest.

### `check_deadline`

Returns a timeout error when the supplied instant has been reached. Readiness
waiting and reply orchestration reuse this check.

### `timeout_error`

Constructs the common I/O `TimedOut` error. It describes the local deadline
without claiming a remote filtering condition is proven.

### `send_tcp_header`

Borrows the registered raw socket and header. It constructs the raw destination,
checks the deadline, awaits writable readiness under that deadline, checks time
again, and attempts `send_to` through `try_io`. A complete write returns `Ok(())`.
An unexpected short write produces `WriteZero`; remaining bytes are not sent as
a second packet. Interrupted operations and stale readiness are retried under
the same deadline; other I/O errors propagate.

### `receive_raw_packet`

Allocates the receive buffer, checks the deadline, awaits readable readiness,
checks time again, and calls `recv` through `try_io`. It returns one packet's
initialized bytes as a vector. It retries temporary conditions but does not
discard unrelated TCP packets: identifying those is still future work.

### `parse_ipv4_packet`

Checks minimum size, IPv4 version, header length, total length, TCP protocol,
header checksum, and fragmentation. It then extracts source and destination
addresses and returns a TCP segment slice limited to the declared total length.
It does not validate the TCP segment or establish that the packet answers our
probe. Tests cover malformed lengths, checksum failures, fragments, options,
and exclusion of trailing bytes beyond declared packet length.

### `parse_tcp_reply`

Checks minimum segment size and the header length encoded in byte 12's upper
four bits. It builds a pseudo-header using the received addresses and complete
TCP segment length, then verifies the checksum without modifying the received
checksum field. It extracts ports as `u16`, sequence and acknowledgment as `u32`,
and flags directly from byte 13, returning a `TcpReply`. Options and payload are
included in checksum input even though they are not returned as parsed fields.

### `match_syn_reply`

Checks that received source/destination addresses and ports are reversed relative
to the original probe. A reply to local port 40000 targeting remote port 80 must
come from remote port 80 back to local port 40000.

It requires ACK and compares the received acknowledgment with the probe's
sequence number plus one, calculated using `wrapping_add(1)`. SYN consumes one
sequence number. The remote sequence number is independent and may legitimately
be zero; it is not the value to compare against our expected acknowledgment.

Finally it rejects FIN, SYN+RST together, and replies with neither SYN nor RST.
It returns `Ok(true)` for an accepted response and `Ok(false)` for a mismatch.
A nonmatching packet is not a local program failure. Matching correlates a reply
with the probe; it does not authenticate the sender or prove service identity.
The current policy does not accept RST replies lacking ACK.

### `classify_syn_reply`

Maps an already parsed, validated, matching reply to a measured port state. The
caller must run the parsers and matcher first: this function reads flags only;
it does not check addresses, acknowledgment numbers, or checksums.

The implementation extracts these booleans using integer masks:

| Boolean | Mask | Meaning when the masked value is nonzero |
| --- | --- | --- |
| `_fin` | `0x01` | FIN is set. |
| `_syn` | `0x02` | SYN is set. |
| `_rst` | `0x04` | RST is set. |
| `_ack` | `0x10` | ACK is set. |

It then rejects unsupported combinations with this condition:

```rust
if !_ack || _fin || _syn == _rst {
    return Ok(None);
}
```

`!_ack` means ACK is absent. `_fin` means FIN is present. `_syn == _rst`
is true when both booleans are true or both are false: we require exactly one
of SYN and RST. If this guard passes, SYN means open; otherwise RST must be set
and means closed under the matching policy.

| Relevant flags | Returned value |
| --- | --- |
| SYN + ACK, no RST or FIN | `Ok(Some(PortStatus::Open))` |
| RST + ACK, no SYN or FIN | `Ok(Some(PortStatus::Closed))` |
| Missing ACK, FIN, both SYN/RST, or neither SYN/RST | `Ok(None)` |

Masking individual bits permits additional flags such as ECE to be present.
Comparing the entire flags byte with a single constant would be more restrictive.
This is the project's current supported-response policy, not a full TCP stack.

The nested return type is `Result<Option<PortStatus>, String>`:

- `Ok(Some(status))`: classification succeeded and produced a state.
- `Ok(None)`: no supported classification; this does not mean closed.
- `Err(message)`: the interface permits a classification error, though the
  current implementation has no error branch.

Timeouts have no received flags and are handled by scan orchestration, not this
function. Cleanup failure must not erase a measured open state. The relevant
TCP fields are documented in [RFC 9293, section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1).

### `build_rst_header`

Builds a 20-byte reset for an already validated, matching SYN/ACK:

1. Start with a zero-filled TCP header.
2. Write the original probe's source and destination ports. The reset travels
   from our computer back to the target, just like the original SYN.
3. Copy the received acknowledgment into the reset's sequence field, bytes 4–7.
4. Set byte 12 to `0x50` (20-byte header) and byte 13 to `0x04` (RST only).
5. Keep acknowledgment, window, and urgent pointer zero.
6. Calculate the checksum last using the original source/destination addresses.
7. Return the completed array.

For example, if our SYN used sequence 1000 and the SYN/ACK acknowledged 1001,
the reset's sequence is 1001. Do not add another one or copy the remote sequence.
The reset's ACK flag is absent, so its acknowledgment field remains zero.
This follows the ACK-bearing segment case in
[RFC 9293, reset generation](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.2).

Single-byte fields use assignment, such as `header[13] = 0x04`. Multi-byte fields
use `to_be_bytes` and `copy_from_slice`. The checksum helper mutates the array;
its call ends with `?;`, while the final `Ok(header)` has no semicolon.
The builder assumes its reply has already been validated and matched.

### `cleanup_syn_probe`

Builds and sends a reset for an already validated, matching open-port reply.
It borrows the registered socket, original probe, reply, and cleanup deadline.
The function returns `std::io::Result<()>`; it does not return or overwrite a
`ScanResult`.

The implementation proceeds in three stages:

1. **Guard the operation.** Call `classify_syn_reply`. If the flag combination is
   not classified as open, return `Ok(())` without building or sending a reset.
   This avoids responding to RST/ACK or unsupported combinations. This guard
   only checks flags: the caller must still perform packet validation and probe
   matching first.
2. **Build the bytes.** Call `build_rst_header` and retain its array. Convert a
   builder error from `String` into an I/O `InvalidData` error with `map_err`;
   `?` then returns that error early. Conversion is required because the two
   helpers have different error types.
3. **Send within the deadline.** Borrow the reset array and pass it to
   `send_tcp_header` with the same registered socket, the probe's destination IP,
   and the supplied deadline. Await and return its result.

`send_tcp_header` sends any supplied 20-byte TCP header unchanged. It does not write SYN flags itself. Reusing it preserves
the reset's `0x04` flags and avoids duplicating readiness, timeout, byte-count,
Interrupted, and WouldBlock handling. The name now describes both SYN and reset transmission.

The final awaited send expression has no semicolon because its I/O result is the
cleanup function's return value. The socket and array are borrowed; the helper
does not take ownership of the caller's registered socket.

An already expired deadline means no send attempt for an open reply. A non-open
reply is a successful no-op even if that deadline has expired, because there is
no cleanup operation to perform. The helper does not wait for acknowledgment of
the reset and does not add a network retransmission policy.

**The caller must preserve the measured port state.** If SYN/ACK already established
an open result and cleanup fails, retain `Open` and attach a separate diagnostic
observation. Do not replace the measurement with `Unknown` or a timeout label.
If the probe deadline has already expired, cleanup may have no remaining time;
the caller caps cleanup at 100 ms of the remaining probe budget.

Linux's normal TCP stack may generate a reset independently of our raw socket.
This helper neither disables nor detects that behavior. Packet-level cleanup
has not been validated in a live scan. The helper is now called through the
reply orchestration callback.

### Supporting models and `map_syn_result`

[src/model/syn.rs](../src/model/syn.rs) defines three small data containers:

- `ParsedIpv4Packet<'a>` owns its IP address values but borrows the TCP bytes.
- `TcpReply` contains fields extracted from a validated TCP segment.
- `SynProbe` retains the original endpoints and sequence number for matching.

The lifetime `'a` connects the borrowed TCP slice to the input packet's lifetime.
It prevents retaining that view after the owning receive vector has been dropped.

[map_syn_result](../src/mapper/syn.rs) constructs the final TCP `ScanResult`
from measured status and diagnostic fields. Application service and banner fields
remain empty. Its return type is now directly `ScanResult`: constructing this
record has no failure path, so an extra `Result` wrapper is unnecessary.

## 12. Library functions and methods

| API or syntax | Purpose in this implementation |
| --- | --- |
| `Instant::now`, `elapsed` | Measure local time spent. |
| `target.ip`, `target.port` | Read the destination endpoint. |
| `Ipv4Addr::octets` | Obtain an IPv4 address's four bytes. |
| `to_be_bytes`, `from_be_bytes` | Encode and decode network-order integers. |
| `copy_from_slice` | Copy equal-length byte slices into header fields. |
| `as_chunks::<2>()` | Process checksum words and a possible odd byte. |
| `Vec::with_capacity` | Reserve storage without adding elements. |
| `extend_from_slice` | Append actual bytes; unlike capacity reservation, changes length. |
| `wrapping_add` | Add modulo the integer width; use only where wraparound is intended or bounded. |
| `Socket::new` | Create an OS socket of a chosen domain, type, and protocol. |
| `bind`, `local_addr` | Choose and inspect a local endpoint. |
| `as_socket` | Convert an OS address to an optional standard IP socket address. |
| `set_nonblocking` | Configure operations to return WouldBlock instead of waiting. |
| `AsyncFd::register` | Register and own a socket within Tokio's reactor. |
| `readable`, `writable` | Await an opportunity to perform an operation. |
| Guard `try_io` | Attempt an operation and manage stale readiness. |
| `get_ref` | Borrow the socket inside AsyncFd. |
| `send_to`, `recv` | Attempt packet transmission and reception. |
| `Error::new`, `ErrorKind` | Create and categorize I/O failures. |
| `error.kind()` | Compare the category without parsing an error message. |
| `timeout_at` | Bound a future with an absolute deadline. |
| `map_err`, `ok_or` | Transform errors or convert an option into a result. |
| `MaybeUninit::uninit`, `assume_init` | Prepare receive storage and read only proven initialized bytes. |
| `iter`, `map`, `collect` | Convert the received prefix into an owned vector. |

## 13. Tests and development commands

Tests are in [tests/scan/syn.rs](../tests/scan/syn.rs) and
[tests/scan/syn_flow.rs](../tests/scan/syn_flow.rs). `#[cfg(test)]` and relative
`#[path = "../../../tests/scan/..."]` declarations attach them to the SYN module
root. This is why they access sibling helpers through `super::packet`,
`super::reply`, or `super::socket`. They are not standalone Cargo integration tests.

`#[test]` marks a synchronous test. `#[tokio::test]` supplies a runtime for an
async test. `assert_eq!` checks equality; `assert_ne!` checks inequality.
`unwrap()` in these tests makes an unexpected setup failure fail the test.

Current coverage includes:

- Port encoding and zero-filled headers.
- Field offsets and preservation of unrelated header bytes.
- Even/odd checksum input, carry handling, and a large-input overflow regression.
- Pseudo-header layout, checksum replacement, and a complete expected SYN fixture.
- Detection of changed checksum inputs.
- An expired-send deadline using a local Unix socket pair, without a network probe.
- Matching accepted SYN/ACK and RST/ACK responses and rejecting contradictory flags.
- Rejecting an incorrect acknowledgment and accepting expected sequence wraparound.
- Classifying supported replies, allowing additional ECE flags, and returning no
  classification for unsupported flag combinations.
- A complete reset-header fixture checking original endpoints, the reply's ACK
  as reset sequence, RST-only flags, zero fields, and checksum.
- Cleanup guard behavior: non-open replies require no send; open replies honor
  an expired deadline. The test uses a local Unix socket pair and sends no data.
- Parser coverage for truncated IPv4/TCP input, header and total lengths, checksum
  errors, fragmentation, IP/TCP options, odd payloads, and trailing input bytes.
- Flow coverage for malformed/unrelated traffic followed by a matching reply,
  closed results without cleanup, local receive errors, silence, expired deadlines,
  continuous invalid traffic, and cleanup failure/timeout preserving open results.
- A local idle Unix socket pair verifies receive-deadline behavior without traffic.
- Progress and reporting retain TCP transport and cleanup diagnostics.


`checksum_input` in the test file joins the fixed pseudo-header and a supplied
header for assertions. The fixed addresses are documentation addresses, not
targets contacted by the tests. The fixture uses source port 40000, destination
port 80, sequence 1, window 1024, and expected checksum `0x22ff`.

The Unix socket-pair test does not prove that raw TCP works: it specifically
checks that an expired deadline prevents I/O even on a writable resource.
Receive-path behavior and live packet correctness need additional verification.

```bash
cargo fmt --check
cargo check --locked --offline
cargo test --locked --offline scan::syn::tests
cargo test --locked --offline
```

`cargo fmt` applies formatting; `--check` only verifies it. `cargo check` checks
types and compilation without running the scanner. `cargo test` executes tests,
so always understand their behavior before treating them as non-networking.

`--locked` requires the lockfile to match the manifest. `--offline` disallows
dependency downloads. If a new dependency was added, `cargo check --offline`
may update the lockfile, but still needs the crate cached. Dependency resolution
can update the lockfile before an unavailable download causes compilation to fail.

`cargo build --release` creates an optimized executable under `target/release`.
It does not install the binary on PATH. `cargo install --path . --locked` installs
it in Cargo's binary directory, which must be on PATH. A previously installed
`rmap` may be older than the source you are editing; `cargo run` uses this project.

## 14. What remains unfinished

The basic IPv4 SYN pipeline is wired for version 0.5.0, and its offline tests
cover parsing, matching, classification, invalid/unrelated packets, deadline
expiration, local receive errors, and cleanup failures that preserve open results.
This is implementation-level completion, not live raw-packet validation.

Next validation and later work:

1. Validate a small explicit port list on an authorized test host with appropriate
   raw-socket privileges. This has not been performed by the assistant.
2. Observe SYN/SYN-ACK/RST behavior with packet capture, including any resets sent
   independently by the Linux kernel. Test a known open port, closed port, and silence.
3. Evaluate file-descriptor limits, per-probe raw socket traffic duplication,
   receive-buffer memory, and performance before increasing concurrency.
4. Add visible local-failure summaries for open-only full scans. An empty table
   currently does not prove all probes succeeded.
5. Consider ICMP error interpretation and a bounded retransmission policy later;
   neither is included in this initial implementation. IPv6 SYN is also unsupported.
6. Expand application probing (HTTP on other ports, TLS, SMB, RPC/NFS) separately.
   SYN packets alone do not provide application banners or software versions.

Measured results remain independent of optional AI interpretation. Service hints,
banners, and model hypotheses must not become unverified port-state facts.

## 15. Reading list

Read a small section, then return to the corresponding function in this project.

### Rust fundamentals

- [Rust Book: ownership](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html): why retaining a socket matters.
- [Rust Book: references](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html): `&`, `&mut`, and borrowing a header or socket.
- [Rust Book: match](https://doc.rust-lang.org/book/ch06-02-match.html): extracting enum values and binding names.
- [Rust Book: Result and error propagation](https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html): `Ok`, `Err`, and `?`.
- [Rust Book: closures](https://doc.rust-lang.org/book/ch13-01-closures.html): functions passed to `try_io` and `map`.
- [MaybeUninit documentation](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html): initialization and the unsafe contract.

### Sockets and asynchronous operations

- [socket2 0.5.10 Socket](https://docs.rs/socket2/0.5.10/socket2/struct.Socket.html): creation, binding, sending, and receiving.
- [socket2 raw type feature](https://docs.rs/socket2/0.5.10/socket2/struct.Type.html#associatedconstant.RAW): why the `all` feature is enabled.
- [Rust UdpSocket](https://doc.rust-lang.org/std/net/struct.UdpSocket.html): the temporary source-IP helper.
- [Linux ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html): local addresses and socket binding.
- [Linux raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html): raw TCP behavior and IPv4 headers.
- [Tokio AsyncFd](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html): registration and ownership.
- [Tokio readiness guard try_io](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFdReadyGuard.html#method.try_io): stale readiness and nested results.
- [Tokio timeout_at](https://docs.rs/tokio/latest/tokio/time/fn.timeout_at.html): shared deadlines and immediately ready futures.

### Protocol concepts

- [RFC 9293, TCP header](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1): field layout and checksum coverage.
- [RFC 1071, Internet checksum](https://www.rfc-editor.org/rfc/rfc1071.html): one's-complement arithmetic.
- [Nmap SYN scan explanation](https://nmap.org/book/synscan.html): packet exchange diagrams and port-state interpretation.
- [Nmap service detection](https://nmap.org/book/man-version-detection.html): why application identification is a later phase.

The protocol standards describe behavior; Linux manuals explain the OS interface;
Rust and crate documentation explain how our program expresses it. Use all three
layers when a detail is unclear.

## 16. Learning to parse packet bytes

### What "low level" means in this project

You are working with two kinds of contracts:

- A protocol defines what each byte and bit means on the wire.
- An OS API defines how your program exchanges bytes with a socket.

Rust supplies arrays, slices, integers, and error handling to express those
contracts. There is no automatic relationship between a received byte array and
your `TcpReply` struct: the parser must check and translate the fields.

Parsing bytes with checked indexing and explicit integer conversions can remain
safe Rust. Low-level networking does not mean every operation needs `unsafe`.
Our unsafe blocks have specific contracts around socket registration and
initialized receive-buffer bytes.

### How to read a header diagram

The IPv4 and TCP standards draw headers as rows of 32 bits: four bytes per row.
Start counting byte indexes from zero. Follow each field's width and position,
then compare it with the parser's indexing. Multi-byte integer fields use
big-endian conversion; one-byte bit fields need masks or shifts.

The table below summarizes fields used by our current code and next exercise.
The layouts come from [IPv4 section 3.1](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1)
and [TCP section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1).

| Header | Byte indexes | How our parser interprets the field |
| --- | --- | --- |
| IPv4 | 0, upper four bits | Version: shift right by four; require 4. |
| IPv4 | 0, lower four bits | IHL: mask with `0x0F`, then multiply by four. |
| IPv4 | 2–3 | Total packet length: read as big-endian `u16`. |
| IPv4 | 6–7 | Flags and fragment offset: read as big-endian `u16`, then mask. |
| IPv4 | 9 | Payload protocol: require 6 for TCP. |
| IPv4 | 12–15 | Source address: four octets. |
| IPv4 | 16–19 | Destination address: four octets. |
| TCP | 12, upper four bits | Data offset: shift right by four, then multiply by four. |

The TCP indexes start at the beginning of `tcp_segment`, not the beginning of
the original IPv4 buffer. Use the validated IPv4 header length to locate it.

### A mask versus a shift

Take the example byte `0x45`:

```text
0x45                 = 0100 0101
0x45 >> 4            = 0000 0100 = version 4
0x45 & 0x0F          = 0000 0101 = IHL 5
IHL 5 times 4 bytes  = 20 bytes of IPv4 header
```

For TCP, byte 12 might be `0x50`: the upper four bits contain 5, so its header
is 20 bytes. IPv4 IHL and TCP data offset use different positions, even though
both encode a count of four-byte words.

`&` on integers performs a bitwise AND. `&&` combines boolean conditions;
`||` accepts either boolean condition. These are different operations. A
validation guard usually joins independent reasons for rejection using `||`.
See the [Rust Reference on operators](https://doc.rust-lang.org/reference/expressions/operator-expr.html#arithmetic-and-logical-binary-operators).

### Length checks must precede slicing

Our parser uses the following sequence:

1. Require 20 received bytes before reading fixed IPv4 fields.
2. Require version 4 before interpreting the layout as IPv4.
3. Require `20 <= header_len <= bytes.len()`.
4. Require `header_len <= total_len <= bytes.len()`.
5. Verify the protocol and IPv4 header checksum.
6. Reject unsupported fragmentation.
7. Borrow `bytes[header_len..total_len]` as the TCP segment.

These checks prevent unsafe assumptions and out-of-bounds panics. For a 44-byte
IPv4 packet with a 24-byte header, TCP starts at byte 24, not byte 20. If the
received buffer has extra bytes after the declared packet end, the parser does
not include them in the returned TCP segment.

TCP parsing needs its own minimum-size check and data-offset validation. A
valid IPv4 header does not prove that its payload is a valid TCP header.

### Fragmentation check

The current parser reads the combined flags/offset word and rejects either:

- `fragment & 0x2000 != 0`: more fragments follow.
- `fragment & 0x1FFF != 0`: this piece has a nonzero fragment offset.

The parser does not reassemble fragments. The Don't Fragment flag alone is
allowed. This is our parser's explicit scope, not a claim that every packet
delivered by the OS will necessarily arrive fragmented.

### A short reading path

Read these in order, using your code to connect the explanation to an example:

1. [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/html/split/):
   start with chapters 2 and 3 for sockets, IP addresses, ports, and byte order;
   then chapter 5 for socket operations. Its examples are C, but the OS concepts
   carry over to Rust's socket APIs.
2. [RFC 791, section 3.1](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1):
   read the IPv4 header diagram beside `parse_ipv4_packet`.
3. [RFC 9293, section 3.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1):
   read the TCP header diagram beside `write_syn_fields` and `parse_tcp_reply`.
4. [Rust Reference: operators](https://doc.rust-lang.org/reference/expressions/operator-expr.html):
   use it when masks, shifts, comparisons, and boolean operators look similar.
5. [Rust Book: unsafe Rust](https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html):
   learn why our two unsafe operations require explicit reasoning; this is
   background for reviewing them, not a reason to make the packet parser unsafe.

For each field, ask: where is it, how wide is it, how is it encoded, and what
must be checked before using it? Answering those four questions is the core
skill behind these parsing exercises.
