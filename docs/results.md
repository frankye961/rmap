# Understanding scan results

Each report row includes the port, connection state, an optional service label, the elapsed time, and a detail. For TCP, elapsed time measures the initial connection attempt and excludes later banner reads or HTTP/HTTPS/RPC probes. For UDP, it measures socket setup, sending, and waiting for a response.

| State | What it means here |
| --- | --- |
| `open` | The TCP connection succeeded or a UDP response was received. This alone does not identify a service or prove a vulnerability. |
| `closed` | The TCP connection was refused, or the OS reported a refused UDP probe. |
| `filtered` | The connection timed out. Filtering is a tentative explanation, not a confirmed fact. |
| `open\|filtered` | No UDP response arrived before the read timeout; an open service may silently ignore the probe. |
| `undetermined` | Another socket or I/O error prevented classification. |

For most open TCP ports, the scanner passively reads up to 512 bytes, stopping at a newline, a read timeout, a closed connection, or the byte limit. `ScanResult.banner` preserves the collected bytes, while `observation` records the stop reason separately. A complete supported SSH identification line gives the port an `ssh` service label. For OpenSSH, identification also stores the product, software version, and optional distribution comments separately; for example, `OpenSSH`, `10.0p2`, and `Debian-7+deb13u4`. Unknown SSH implementations retain an `ssh` label without guessed product/version fields. Other banners are retained even when the service is unknown.

### FTP and SMTP identification

Supported FTP banners identify vsFTPd and FileZilla Server, including a version when advertised in a supported format. SMTP identification requires a complete CRLF-terminated greeting starting with `220 ` or `220-` and containing a separate, uppercase `SMTP` or `ESMTP` token. A `220` code alone does not identify SMTP because FTP also uses it. Identification uses banner content, including on nonstandard ports.

For SMTP, the parser searches the greeting for a separate `Postfix` or `Exim` token and reads the immediately following token as a possible version. A version must start with an ASCII digit and contain only ASCII letters, digits, dots, hyphens, or underscores. Missing or unsupported product/version text remains unknown; the service can still be identified as `smtp`.

| Example banner | Service | Product | Version |
| --- | --- | --- | --- |
| `220 mail.example.test ESMTP Postfix` | smtp | Postfix | Unknown |
| `220 mail.example.test ESMTP Exim 4.98` | smtp | Exim | 4.98 |
| `220 mail.example.test ESMTP ready` | smtp | Unknown | Unknown |

These are parser examples, not live scan results. SMTP identification is passive: rmap does not send `EHLO`, negotiate `STARTTLS`, or probe SMTP over implicit TLS. Slash-style product/version tokens and complete multiline greeting collection are not implemented. The banner reader stops after receiving a newline, so identification cannot rely on later greeting lines. Banners are self-reported observations, not verified software identities or vulnerability findings.

Reporting creates a printable preview from at most 64 banner bytes, escapes control bytes, and removes a trailing line ending. Longer banners receive a truncation marker. When reading stops after receiving some data, the report includes both the preview and the stop reason, such as `partial banner (read timed out)`. Creating this preview does not shorten or modify the stored bytes.

For open ports 80, 8000, 8080, and 8888, the scanner automatically makes an HTTP `HEAD` request. These ports select a probe; a valid response establishes the `http` label, even without a `Server` header. The report shows an escaped preview of that header when present. The HTTP probe does not follow redirects or use a configured proxy. It does not display HTTP status codes. A failed probe or banner read does not change a successful TCP connection into a closed result.

Open ports 443 and 8443 use an HTTPS `HEAD` request with TLS verification enabled.
Successful responses are labeled `https`; errors remain probe observations on an
open TCP result. A port number by itself does not establish HTTPS.

The original `Server` header is parsed before display truncation. A single product
such as `Caddy`, or a product/version such as `Apache/2.4.68`, populates
`ScanResult.service_information`. One optional parenthesized comment is preserved
separately: `Apache/2.4.68 (Debian)` supplies product `Apache`, version `2.4.68`,
and comment `Debian`. Missing, undecodable, malformed, or unsupported headers keep
HTTP or HTTPS identified with unknown software fields. Multiple products and nested or
multiple comments are outside this initial parser's scope. These are advertised
software details; a comment such as `Debian` is not confirmed OS detection.

Service labels are deliberately limited. A program can run on an unexpected port, and a banner or `Server` header can be missing, misleading, or customized. The scanner does not verify a product version beyond the bytes it observed.

UDP uses a fresh local socket for each port and restricts responses to that target's IP and port. Empty probes are deliberately simple: many UDP services require a valid protocol request and will ignore them. Service identification and protocol-specific UDP probes are not implemented. Closed-port errors depend on what the operating system exposes; silence is never treated as proof of an open or closed port. Response previews escape control bytes and are limited to 64 bytes; datagrams are read into a 1024-byte buffer and may be truncated.
