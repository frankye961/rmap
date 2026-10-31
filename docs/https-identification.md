# HTTPS identification and learning notes

rmap automatically selects HTTPS probes on confirmed-open TCP ports 443 and 8443.
HTTP candidates remain 80, 8000, 8080, and 8888. These are probe-selection hints;
the port number alone does not establish which service is running.

## How the code fits together

1. `tcp::scan_port` establishes a TCP connection and records the open state and
   connection duration. It selects an active probe for HTTP or HTTPS candidates.
2. `http::probe_request` chooses `head_request` or `https_head_request`. Building
   a request does not perform a network operation. Both return
   `Result<Request, reqwest::Error>`; `?` propagates a construction failure.
3. `http::probe` records whether the URL scheme is `https` before passing
   ownership of the request into `client.execute(request).await`. The existing
   timeout bounds the request, including TLS work. Redirects and proxies are off.
4. Only after execution succeeds does `response_information` parse the original
   `Server` header. It uses the existing product/version/comment parser and sets
   the service to `https` for the HTTPS request. Transport remains TCP.
5. `tcp::apply_http_probe_result` uses the existing service mapper to store the
   fields in `ScanResult`. The console retains its escaped `Server:` preview.
   Missing or unusable headers leave software fields unknown while keeping the
   established HTTP or HTTPS protocol label.
6. Request errors produce a probe-failure observation. They preserve the open
   TCP result and connection timing, without assigning a service from the port.

The original TCP connection is dropped before the separate web request. This
preserves the one-socket-per-active-TCP-probe budget. SYN mode remains port
discovery without application probing.

## TLS validation and scope

The existing Rustls-enabled Reqwest client is reused; no dependency was added.
Certificate trust and name verification remain enabled. Numeric IP targets can
fail validation when a certificate names only a hostname. Self-signed or expired
certificates may also prevent identification. There is no bypass, automatic HTTP
fallback, custom hostname/SNI input, certificate inventory, or TLS fingerprinting.
A failed HTTPS probe is not evidence that the TCP port is closed.

The official Reqwest documentation describes the defaults for
[certificate validation](https://docs.rs/reqwest/0.13.5/reqwest/struct.ClientBuilder.html#method.tls_danger_accept_invalid_certs)
and [name verification](https://docs.rs/reqwest/0.13.5/reqwest/struct.ClientBuilder.html#method.tls_danger_accept_invalid_hostnames).
For protocol background, read
[RFC 9110, HTTPS URI scheme](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2).

## Offline evidence and its limits

The tests in `tests/scan/http.rs` and `tests/scan/tcp.rs` cover:

| Case | Expected behavior checked with fixtures |
| --- | --- |
| Ports 443 and 8443 | Selected as HTTPS candidates, distinct from HTTP candidates |
| A selected HTTP or HTTPS port | HEAD request has the expected scheme, address, port, path, and no body |
| HTTPS response fixture with a Server header | HTTPS label, TCP transport, and parsed software fields |
| Missing, empty, malformed, or undecodable Server header | HTTPS remains identified; software fields are unknown |
| Structured HTTPS result applied to an open port | Identification reaches the result; state and elapsed time are preserved |
| Deterministic request-building failure | An open result stays open and receives a failure observation without an invented service |

The failure fixture exercises the common error path; it does not reproduce a
certificate or handshake error. Response fixtures represent successfully
executed requests; they do not establish that a live TLS exchange works.

No live scans, TLS handshakes, packet captures, or AI requests were performed for
this work. Live behavior remains to be checked in an authorized lab with a known
HTTPS service and a certificate valid for the scanned IP. Record expected and
measured outcomes separately, including a comparison with a host whose
certificate cannot be validated. Do not present expected outcomes as findings.

RPC/NFS, SMB, and OS detection remain separate work. BreachMap assessment and
policy evaluation have been deferred while service identification is completed.
