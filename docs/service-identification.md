# Service identification

## HTTPS identification

TCP connect scans now also select HTTPS probes for confirmed-open ports 443 and
8443. A successful HTTP response over TLS supplies the `https` service label;
the transport remains TCP. Product, version, and comments use the existing
`Server` header parser. Missing headers still allow protocol identification.

Certificate trust and name verification remain enabled. A self-signed, expired,
or name-mismatched certificate can prevent identification, especially when
scanning an IP address with a certificate issued for a hostname. Probe failure
preserves the open-port measurement. There is no certificate bypass, automatic
plaintext fallback, or TLS certificate inventory in this implementation.

The HTTPS extension added six offline tests covering request selection, response
labels, and scan-result integration. Real TLS handshakes,
certificate failures, and live HTTPS servers have not been validated here.
See [HTTPS identification and learning notes](https-identification.md).

## TCP RPC identification

RPC work now includes request encoding, TCP record construction, NULL-reply
validation, and candidate selection for TCP port 111. A completed, validated
portmapper v2 NULL reply maps to `rpcbind` using the existing service mapper.
The observation records program 100000 and protocol version 2; software product
and version remain unknown. A port number alone never establishes this identity.

The TCP result handler accepts completed exchange results, retains connection
measurements and passive banner bytes, and appends RPC diagnostics without
discarding existing observations. Probe failures preserve the open state and
any earlier service identification. Offline tests cover this path and console
formatting.

TCP connect scans now automatically send the portmapper v2 NULL probe on
confirmed-open port 111. The initial connection is closed before the separate
RPC exchange, keeping one live TCP connection per task. Each request uses a
random XID; connecting, writing the complete frame, and reading all fragments
share one identification deadline derived from `--timeout-ms`. The assembled
reply is limited to 4096 bytes, checked before allocating each fragment.

Other TCP ports retain passive banner collection except the NFSv3 and SMB2 candidates
described below. RPC probing adds no flag or dependency and does not run in UDP
or SYN mode. This implementation has
offline tests; no live RPC validation has been performed by the assistant.
See [RPC identification and learning notes](rpc-identification.md).

After successful NULL identification, the scanner now automatically sends a
portmapper v2 DUMP request. Each exchange uses its own XID and `--timeout-ms`
budget, shared across connect/write/read. DUMP accepts at most 128 registrations
within the 4096-byte reply limit; malformed, oversized, or incomplete replies
produce a diagnostic without removing the successful NULL identification.

The console prints a separate advertised-registration table containing program,
program version, transport, and port. An empty successful reply is displayed
explicitly. Registrations do not establish reachability, add measured open ports,
or expand the requested scan scope. Live DUMP interoperability has not been
validated by the assistant; automated checks use fixtures and in-memory streams.

## NFSv3 identification

Confirmed-open TCP port 2049 now receives an NFSv3 NULL probe using RPC program
100003, program version 3, and procedure 0. A validated successful reply labels
the service `nfs` and records the protocol version in the detail. Software
product and release version remain unknown.

The probe reuses the RPC framing and bounded exchange, with one identification
deadline and a 4096-byte reply limit. The initial connection closes before the
probe connection opens. Identification errors preserve the measured open state
and earlier evidence. Port 111 is not required, and RPC registrations do not
trigger scans of additional ports. This first implementation supports TCP
port 2049 and NFSv3; NFSv2/v4 and other ports remain later work. It does not mount
exports or read files. Live NFS behavior has not been validated by the assistant.
See [NFS identification and learning notes](nfs-identification.md).

## SMB identification

In TCP connect mode, confirmed-open port 445 receives a separate SMB2 NEGOTIATE
probe offering dialects 2.0.2 and 2.1. A validated reply supplies the `smb` service
label and negotiated dialect to the normal report and optional AI context
(when included within its eight-observation limit);
software product, software version, and OS remain unknown.

The initial connection closes before probing, preserving one live socket per
task. Connecting, writing, and reading share one identification deadline with a
4096-byte reply limit. Failures append a diagnostic without changing the measured
open state or connection time. No authentication, share enumeration, port 139,
SMB1, or SMB3 negotiation is implemented. Offline tests cover byte encoding,
framing, malformed responses, timeouts, and scanner integration; live SMB
interoperability remains unverified. The wire format follows Microsoft's
[SMB2 negotiation specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/77f696b8-9aa0-4ed1-abb2-c097c0ccb05a).
See [SMB identification and learning notes](smb-identification.md) for the
function flow, byte layout, error handling, and controlled-lab experiment.

The current application accepts individual IPv4 addresses, target lists, and CIDR
subnets. It scans each unique host once using TCP connect, IPv4 TCP SYN, or UDP
probes. TCP connect mode collects limited banners and selects HTTP, HTTPS,
portmapper, NFSv3, and SMB2 probes on supported candidate ports. Optional DeepSeek interpretation can
research public CVEs and exploit references using a web search tool. Host
discovery, broader service fingerprinting, OS detection, and additional scan
methods remain future work.
