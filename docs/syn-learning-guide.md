# Learning Rust and networking through rmap's SYN scanner

This guide explains the concepts and functions used while building the SYN
scanner in [src/scan/syn.rs](../src/scan/syn.rs). Read it alongside that file.
Examples describe the current implementation; they are not instructions to run
a live scan.

The focus is the SYN work we have completed together: Rust syntax, ownership,
socket setup, packet construction, checksums, asynchronous sending, and receiving.
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
11. [Every function in syn.rs](#11-every-function-in-synrs)
12. [Library functions and methods](#12-library-functions-and-methods)
13. [Tests and development commands](#13-tests-and-development-commands)
14. [What remains unfinished](#14-what-remains-unfinished)
15. [Reading list](#15-reading-list)

## 1. Current state and overall flow

The code builds a TCP SYN header, prepares and registers a raw socket, sends the
header, and waits for one raw packet. It does not yet validate or match that packet
to the probe. It still returns an `Unknown` port state.

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
Send SYN -> receive one raw IPv4 packet
    |
UNFINISHED: parse, validate, match, classify, and clean up
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
types behind a common interface. The port-allocation helper currently uses it
because it also parses an address string. A helper containing only I/O failures
can often use the simpler `std::io::Result` instead.

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

`connect(target)` binds a UDP socket to `0.0.0.0:0`, associates it with the
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

## 11. Every function in syn.rs

The names are better navigation anchors than line numbers, which change after edits.

### `scan_port`

Input: a destination `SocketAddr` and timeout. Output: a `ScanResult`.
It orchestrates address discovery, allocation, sequence generation, header building,
socket setup, registration, sending, and receiving. Every setup error returns an
`Unknown` result with its actual message and elapsed time. Successful reception
still returns `Unknown`, because `_packet` has not been interpreted.

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

### `connect`

Despite its general name, this is the UDP-based source-IP discovery helper.
It binds a temporary UDP socket, associates the destination, and returns the local
IP. Its socket is dropped on return. It does not create a TCP connection or perform
the SYN scan itself.

### `create_unconnected_tcp_socket`

Creates a stream/TCP socket, builds a local source-IP/port-zero address, binds,
reads `local_addr`, converts `SockAddr` using `as_socket`, extracts the port,
and returns `(Socket, u16)`. It neither connects nor listens. Returning the
socket lets the caller retain the reservation.

### `prepare_raw_tcp_socket`

Creates an IPv4 raw TCP socket, binds the source IP with port zero, enables
nonblocking mode, and returns the owned socket. Setup failures propagate as
I/O errors. It does not register with Tokio; `scan_port` does that afterward.

### `send_syn_probe`

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

## 12. Library functions and methods

| API or syntax | Purpose in this implementation |
| --- | --- |
| `Instant::now`, `elapsed` | Measure local time spent. |
| `target.ip`, `target.port` | Read the destination endpoint. |
| `Ipv4Addr::octets` | Obtain an IPv4 address's four bytes. |
| `to_be_bytes`, `from_be_bytes` | Encode and decode network-order integers. |
| `copy_from_slice` | Copy equal-length byte slices into header fields. |
| `chunks_exact(2)`, `remainder` | Process checksum words and a possible odd byte. |
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

Tests are in [tests/scan/syn.rs](../tests/scan/syn.rs). `#[cfg(test)]` and
`#[path = "../../tests/scan/syn.rs"]` attach them as a unit-test submodule of
`syn.rs`; this is why they can access private parent helpers through `super`.
They are not standalone Cargo integration tests.

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

The next work is interpreting `_packet`, not assuming it answers the probe.

1. Validate minimum IPv4 length and version.
2. Read the IPv4 header length, validate total length, protocol, and fragmentation.
3. Locate and validate the TCP header and checksum.
4. Match source/destination addresses, reversed ports, and appropriate
   acknowledgment/flags against the retained probe values.
5. Ignore unrelated packets and receive again using the same deadline.
6. Classify valid replies and timeouts, preserving uncertainty and local errors.
7. Implement appropriate RST cleanup, accounting for kernel TCP behavior.
8. Replace the unconditional Unknown result with real measurements.
9. Add packet-parser, matcher, receive/deadline, and error-path tests.
10. Update CLI help and review transport labels so SYN measurements report TCP.

The raw socket currently returns the first received TCP packet, which may be
unrelated. No successful classification should be inferred from that alone.
Raw sockets are also created per probe; their resources and traffic delivery
behavior require review before relying on this architecture at high concurrency.

Later service detection will establish separate application connections as
needed. RPC, SMB, HTTP, and TLS have their own request/response behavior. Port-based
service hints are guesses; banner or protocol evidence is a different information
source. AI interpretation must remain separate from both measured states and
unconfirmed hypotheses.

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
