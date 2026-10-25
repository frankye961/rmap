//! TCP SYN header construction and sending with unfinished response handling.
//! Headers have no TCP options or payload; Linux supplies outgoing IPv4 headers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::model::syn::{ParsedIpv4Packet, SynProbe, TcpReply};
use crate::model::{PortStatus, ScanMode, ScanResult};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use tokio::io::unix::AsyncFd;

/// Future asynchronous SYN probe for one destination port.
///
/// Implementation steps:
/// 1. Determine the local source address, source port, and sequence number.
/// 2. Prepare packet reception before sending the probe.
/// 3. Build the SYN header using build_syn_header.
/// 4. Send through a packet backend and wait within the timeout.
/// 5. Match replies, classify the outcome, and perform required cleanup.
/// 6. Return TCP measurements; reporting and AI remain outside this function.
///
/// Sends one SYN probe; reception and port-state classification remain unfinished.
pub(super) async fn scan_port(target: SocketAddr, timeout: Duration) -> ScanResult {
    let started = Instant::now();
    let destination_ip = match target.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return unknown_result(
                target,
                started.elapsed(),
                "IPv6 is not supported for SYN scanning".into(),
            );
        }
    };
    let source_ip = match connect(target) {
        Ok(IpAddr::V4(ip)) => ip,
        Ok(IpAddr::V6(_)) => {
            return unknown_result(
                target,
                started.elapsed(),
                "IPv6 is not supported for SYN scanning".into(),
            );
        }
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to determine local source IP: {error}"),
            );
        }
    };

    // Retain the socket so the TCP source port stays reserved for this probe.
    let (_source_socket, source_port) = match create_unconnected_tcp_socket(source_ip) {
        Ok((socket, port)) => (socket, port),
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to reserve TCP source port: {error}"),
            );
        }
    };

    let sequence_number = match generate_sequence_number() {
        Ok(sequence) => sequence,
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to generate SYN sequence number: {error}"),
            );
        }
    };

    // Advertise the same 1024-byte window used in the header exercises.
    let window: u16 = 1024;
    let syn_header = match build_syn_header(
        source_ip,
        destination_ip,
        source_port,
        target.port(),
        sequence_number,
        window,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to build SYN header: {error}"),
            );
        }
    };

    let raw_tcp = match prepare_raw_tcp_socket(source_ip) {
        Ok(tcp) => tcp,
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to prepare raw TCP socket: {error}"),
            );
        }
    };

    // SAFETY: raw_tcp owns a valid descriptor that remains open and unchanged
    // while owned by AsyncFd; it is not manually closed or replaced.
    let reg_tcp_raw = match unsafe { AsyncFd::register(raw_tcp) } {
        Ok(socket) => socket,
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to register raw TCP socket: {error}"),
            );
        }
    };

    // Sending and reception share one deadline.
    let deadline = tokio::time::Instant::now() + timeout;
    if let Err(error) = send_syn_probe(&reg_tcp_raw, &syn_header, destination_ip, deadline).await {
        return unknown_result(
            target,
            started.elapsed(),
            format!("Failed to send SYN probe: {error}"),
        );
    }

    let _packet = match receive_raw_packet(&reg_tcp_raw, deadline).await {
        Ok(packet) => packet,
        Err(error) => {
            return unknown_result(
                target,
                started.elapsed(),
                format!("Failed to receive raw TCP packet: {error}"),
            );
        }
    };

    unknown_result(
        target,
        started.elapsed(),
        "Raw TCP packet received; reply validation and matching are not implemented".into(),
    )
}

/// Obtain a sequence number from the operating system's random source.
fn generate_sequence_number() -> Result<u32, getrandom::Error> {
    getrandom::u32()
}

/// Preserve a local setup failure without claiming a remote port state.
fn unknown_result(target: SocketAddr, elapsed: Duration, error: String) -> ScanResult {
    ScanResult {
        port: target.port(),
        transport: ScanMode::Tcp,
        status: PortStatus::Unknown,
        service: None,
        elapsed,
        error: Some(error),
        observation: None,
        banner: None,
        service_information: None,
    }
}

/// Exercise 1:
pub(super) fn port_to_bytes(_port: u16) -> Result<[u8; 2], String> {
    Ok(_port.to_be_bytes())
}

/// Exercise 2: create a zero-filled, 20-byte TCP header buffer.
pub(super) fn empty_tcp_header() -> Result<[u8; 20], String> {
    Ok([0; 20])
}

/// Exercise 3: write the source port at bytes 0..2 and destination at bytes 2..4.
/// Reuse port_to_bytes; leave the other bytes unchanged.
pub(super) fn write_ports(
    _header: &mut [u8; 20],
    _source_port: u16,
    _destination_port: u16,
) -> Result<(), String> {
    let source_bytes = port_to_bytes(_source_port)?;
    let destination_bytes = port_to_bytes(_destination_port)?;

    _header[0..2].copy_from_slice(&source_bytes);
    _header[2..4].copy_from_slice(&destination_bytes);

    Ok(())
}

/// Exercise 4: fill sequence, acknowledgment, length, flags, window, and urgent fields.
/// Sequence: bytes 4..8; acknowledgment: 8..12 (zero); byte 12: 0x50;
/// byte 13: 0x02 (SYN); window: 14..16; urgent pointer: 18..20 (zero).
/// Preserve ports and checksum bytes. Encode multi-byte numbers as big-endian.
pub(super) fn write_syn_fields(
    _header: &mut [u8; 20],
    _sequence_number: u32,
    _window: u16,
) -> Result<(), String> {
    _header[4..8].copy_from_slice(&_sequence_number.to_be_bytes());
    _header[8..12].copy_from_slice(&0u32.to_be_bytes()); // Acknowledgment number
    _header[12] = 0x50; // Data offset and reserved bits
    _header[13] = 0x02; // Flags (SYN)
    _header[14..16].copy_from_slice(&_window.to_be_bytes());
    _header[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

    Ok(())
}

/// Exercise 5: compute the Internet checksum over arbitrary bytes.
/// Sum big-endian 16-bit words, fold carries, and complement the final sum.
/// For an odd byte count, pad with a zero byte for calculation only.
pub(super) fn internet_checksum(_data: &[u8]) -> Result<u16, String> {
    let mut sum: u32 = 0;
    let mut chunks = _data.chunks_exact(2); // Create an iterator over 2-byte chunks (16 bytes words)

    for chunk in &mut chunks {
        // Convert the 2 big-endian bytes into a host u16, then cast to u32
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;

        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    if let Some(&last_byte) = chunks.remainder().first() {
        let word = u16::from_be_bytes([last_byte, 0]) as u32;
        sum = sum.wrapping_add(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Fix: Wrap the casted sum in parentheses before applying the NOT (!) operator
    Ok(!(sum as u16))
}

/// Exercise 6: build the 12-byte IPv4 pseudo-header used by the TCP checksum.
/// Layout: source address (4), destination address (4), zero (1), protocol 6 (1),
/// TCP segment length (2, big-endian). Length includes TCP header and payload only.
/// The pseudo-header is checksum input, not part of the transmitted TCP segment.
pub(super) fn ipv4_pseudo_header(
    _source: Ipv4Addr,
    _destination: Ipv4Addr,
    _tcp_length: u16,
) -> Result<[u8; 12], String> {
    let mut header = [0; 12];
    header[0..4].copy_from_slice(&_source.octets());
    header[4..8].copy_from_slice(&_destination.octets());
    header[8] = 0;
    header[9] = 6;
    header[10..12].copy_from_slice(&_tcp_length.to_be_bytes());
    Ok(header)
}

/// Exercise 7: zero bytes 16..18, checksum pseudo-header plus TCP header, then
/// insert the big-endian checksum at bytes 16..18. Reuse exercises 5 and 6.
/// For this fixed header, TCP length is 20 and combined checksum input is 32 bytes.
pub(super) fn apply_tcp_checksum(
    _header: &mut [u8; 20],
    _source: Ipv4Addr,
    _destination: Ipv4Addr,
) -> Result<(), String> {
    _header[16..18].copy_from_slice(&0u16.to_be_bytes()); // Zero the checksum field

    let pseudo_header = ipv4_pseudo_header(_source, _destination, 20)?;
    let mut checksum_input = Vec::with_capacity(32);
    checksum_input.extend_from_slice(&pseudo_header);
    checksum_input.extend_from_slice(_header);

    let checksum = internet_checksum(&checksum_input)?;
    _header[16..18].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}

/// Exercise 8: combine the earlier helpers to return a complete TCP SYN header.
/// Addresses are needed for the checksum; they are not stored in the TCP header.
/// Propagate helper errors. This function builds bytes only and sends nothing.
pub(super) fn build_syn_header(
    _source: Ipv4Addr,
    _destination: Ipv4Addr,
    _source_port: u16,
    _destination_port: u16,
    _sequence_number: u32,
    _window: u16,
) -> Result<[u8; 20], String> {
    let mut header = [0; 20];
    write_ports(&mut header, _source_port, _destination_port)?;
    write_syn_fields(&mut header, _sequence_number, _window)?;
    apply_tcp_checksum(&mut header, _source, _destination)?;

    Ok(header)
}

fn connect(target: SocketAddr) -> std::io::Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(target)?;
    Ok(socket.local_addr()?.ip())
}

fn create_unconnected_tcp_socket(
    _source_ip: Ipv4Addr,
) -> Result<(Socket, u16), Box<dyn std::error::Error>> {
    let unconn_socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let bind_addr: SocketAddr = format!("{}:0", _source_ip).parse()?;

    unconn_socket.bind(&SockAddr::from(bind_addr))?;
    let addr = unconn_socket
        .local_addr()?
        .as_socket()
        .ok_or("Failed to convert socket address to standard SocketAddr")?;
    let port = addr.port();
    Ok((unconn_socket, port))
}

/// Prepare an IPv4 raw TCP socket bound to the source IP in nonblocking mode.
/// Linux will supply outgoing IPv4 headers; received packets include an IP header.
/// Tokio readiness integration comes later.
fn prepare_raw_tcp_socket(_source_ip: Ipv4Addr) -> std::io::Result<Socket> {
    let raw_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;

    let bind_addr = SocketAddr::from((_source_ip, 0));
    let sock_addr = SockAddr::from(bind_addr);
    raw_socket.bind(&sock_addr)?;
    raw_socket.set_nonblocking(true)?; //sets the socket to non blocking
    Ok(raw_socket)
}

/// Send one complete SYN header before the shared probe deadline.
/// Build the destination SockAddr, await writable readiness, and use try_io.
/// Retry WouldBlock, check the sent byte count, and propagate other errors.
async fn send_syn_probe(
    _socket: &AsyncFd<Socket>,
    _header: &[u8; 20],
    _destination_ip: Ipv4Addr,
    _deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    let destination_addr = SocketAddr::from((_destination_ip, 0));
    let target_socket = SockAddr::from(destination_addr);

    loop {
        if tokio::time::Instant::now() >= _deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SYN send deadline expired",
            ));
        }
        let mut wait = tokio::time::timeout_at(_deadline, _socket.writable())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out waiting to send SYN",
                )
            })??;
        if tokio::time::Instant::now() >= _deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SYN send deadline expired",
            ));
        }
        let outcome = wait.try_io(|registered_socket| {
            registered_socket.get_ref().send_to(_header, &target_socket)
        });

        match outcome {
            Ok(Ok(sent)) => {
                if sent == _header.len() {
                    return Ok(());
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Incomplete SYN packet send",
                    ));
                }
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        };
    }
}

/// Receive one raw IPv4 packet before the same probe deadline.
/// Await readable readiness and use try_io; retry WouldBlock without busy waiting.
/// Return only received bytes, including the IP header; parsing happens separately.
async fn receive_raw_packet(
    _socket: &AsyncFd<Socket>,
    _deadline: tokio::time::Instant,
) -> std::io::Result<Vec<u8>> {
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 65_535];

    loop {
        if tokio::time::Instant::now() >= _deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SYN receive deadline expired",
            ));
        }

        let mut ready = tokio::time::timeout_at(_deadline, _socket.readable())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out waiting for a SYN response",
                )
            })??;

        if tokio::time::Instant::now() >= _deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SYN receive deadline expired",
            ));
        }

        let outcome =
            ready.try_io(|registered_socket| registered_socket.get_ref().recv(&mut buffer));

        match outcome {
            Ok(Ok(received)) => {
                let bytes = buffer[..received]
                    .iter()
                    .map(|byte| {
                        // SAFETY: recv initialized exactly the first `received` bytes.
                        unsafe { byte.assume_init() }
                    })
                    .collect();

                return Ok(bytes);
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

/// Validate IPv4 version, IHL, total length, header checksum, protocol, and
/// fragmentation before borrowing the TCP segment. Do not assume a 20-byte IP header.
fn parse_ipv4_packet(_bytes: &[u8]) -> Result<ParsedIpv4Packet<'_>, String> {
    if _bytes.len() < 20 {
        return Err("Byte length is too small".into());
    }

    let _version = _bytes[0] >> 4;
    let _header_len = usize::from(_bytes[0] & 0x0F) * 4;

    if _version != 4 {
        return Err("Packet is not IPv4".into());
    }

    if _header_len < 20 || _header_len > _bytes.len() {
        return Err("Header length is too big".into());
    }

    let _total_len = usize::from(u16::from_be_bytes([_bytes[2], _bytes[3]]));

    if _total_len < _header_len || _total_len > _bytes.len() {
        return Err("Invalid IPv4 total length".into());
    }

    if _bytes[9] != 6 {
        return Err("IPv4 packet does not contain TCP".into());
    }

    if internet_checksum(&_bytes[.._header_len])? != 0 {
        return Err("Invalid IPv4 header checksum".into());
    }

    let _fragment = u16::from_be_bytes([_bytes[6], _bytes[7]]);

    if _fragment & 0x2000 != 0 || _fragment & 0x1FFF != 0 {
        return Err("Fragmented IPv4 packets are not supported".into());
    }

    let _source = Ipv4Addr::new(_bytes[12], _bytes[13], _bytes[14], _bytes[15]);
    let _destination = Ipv4Addr::new(_bytes[16], _bytes[17], _bytes[18], _bytes[19]);

    Ok(ParsedIpv4Packet {
        source: _source,
        destination: _destination,
        tcp_segment: &_bytes[_header_len.._total_len],
    })
}

/// Validate TCP length, data offset, and pseudo-header checksum, then extract fields.
/// Length and checksum calculations must include any payload and TCP options.
fn parse_tcp_reply(_packet: &ParsedIpv4Packet<'_>) -> Result<TcpReply, String> {
    if _packet.tcp_segment.len() < 20 {
        return Err("TCP segment too small".into());
    }

    let _header_len = usize::from(_packet.tcp_segment[12] >> 4) * 4;

    if _header_len < 20 || _header_len > _packet.tcp_segment.len() {
        return Err("Invalid Header length".into());
    }

    let _segment_length = u16::try_from(_packet.tcp_segment.len())
        .map_err(|_| "TCP segment is too large".to_string())?;

    let _pseudo_header = ipv4_pseudo_header(_packet.source, _packet.destination, _segment_length)?;

    let mut _checksum_vec = Vec::with_capacity(_pseudo_header.len() + _packet.tcp_segment.len());

    _checksum_vec.extend_from_slice(&_pseudo_header);
    _checksum_vec.extend_from_slice(_packet.tcp_segment);

    if internet_checksum(&_checksum_vec)? != 0 {
        return Err("Invalid TCP checksum".into());
    }

    let _source_port = u16::from_be_bytes([_packet.tcp_segment[0], _packet.tcp_segment[1]]);

    let _dest_port = u16::from_be_bytes([_packet.tcp_segment[2], _packet.tcp_segment[3]]);

    let _seq_number = u32::from_be_bytes([
        _packet.tcp_segment[4],
        _packet.tcp_segment[5],
        _packet.tcp_segment[6],
        _packet.tcp_segment[7],
    ]);

    let _ack = u32::from_be_bytes([
        _packet.tcp_segment[8],
        _packet.tcp_segment[9],
        _packet.tcp_segment[10],
        _packet.tcp_segment[11],
    ]);

    let _flags = _packet.tcp_segment[13];

    Ok(TcpReply {
        source_port: _source_port,
        destination_port: _dest_port,
        sequence_number: _seq_number,
        acknowledgment_number: _ack,
        flags: _flags,
    })
}

/// Compare reversed addresses and ports, acknowledgment, and acceptable flags
/// against the original probe. Use wrapping sequence arithmetic; ignore unrelated replies.
fn match_syn_reply(
    _probe: &SynProbe,
    _packet: &ParsedIpv4Packet<'_>,
    _reply: &TcpReply,
) -> Result<bool, String> {
    Err("SYN reply matching is not implemented".into())
}

/// Classify an already validated and matched reply. Return None for a flag
/// combination that does not establish a supported outcome; timeouts are handled separately.
fn classify_syn_reply(_reply: &TcpReply) -> Result<Option<PortStatus>, String> {
    Err("SYN reply classification is not implemented".into())
}

/// Build an appropriate reset for a validated matching SYN/ACK, including its checksum.
/// Do not reuse the SYN builder unchanged: reset flags and sequence handling differ.
fn build_rst_header(_probe: &SynProbe, _reply: &TcpReply) -> Result<[u8; 20], String> {
    Err("TCP reset header construction is not implemented".into())
}

/// Send reset cleanup through nonblocking readiness with a bounded deadline.
/// Account for kernel TCP reset behavior. The caller preserves measured port status
/// independently of cleanup failure; no cleanup or network I/O occurs in this scaffold.
async fn cleanup_syn_probe(
    _socket: &AsyncFd<Socket>,
    _probe: &SynProbe,
    _reply: &TcpReply,
    _deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SYN probe cleanup is not implemented",
    ))
}

#[cfg(test)]
#[path = "../../tests/scan/syn.rs"]
mod tests;
