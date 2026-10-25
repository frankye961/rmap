//! Linux socket setup and nonblocking packet I/O through Tokio readiness.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};

/// Select the local source IP without sending a UDP application datagram.
pub(super) fn discover_source_ip(_target: SocketAddrV4) -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(_target)?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv4 source address required",
        )),
    }
}

/// Retain the returned stream socket to keep its TCP source port reserved.
pub(super) fn create_unconnected_tcp_socket(_source_ip: Ipv4Addr) -> io::Result<(Socket, u16)> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(SocketAddr::from((_source_ip, 0))))?;
    let address = socket.local_addr()?.as_socket().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Local socket address is not an IP address",
        )
    })?;
    Ok((socket, address.port()))
}

/// Linux supplies outgoing IPv4 headers; received packets include the IP header.
pub(super) fn prepare_raw_tcp_socket(_source_ip: Ipv4Addr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(SocketAddr::from((_source_ip, 0))))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Keep permission failures actionable without mislabeling the remote host.
pub(super) fn raw_socket_error(_error: io::Error) -> String {
    if _error.kind() == io::ErrorKind::PermissionDenied {
        return format!(
            "SYN scanning requires raw-socket privileges (CAP_NET_RAW). Run the built executable with sudo or configure that capability: {_error}"
        );
    }
    format!("Cannot prepare raw TCP socket: {_error}")
}

pub(super) fn register_raw_socket(_socket: Socket) -> Result<AsyncFd<Socket>, String> {
    // SAFETY: AsyncFd owns the socket; its descriptor stays open and unchanged
    // until the wrapper is dropped. We never manually close or replace it.
    unsafe { AsyncFd::register(_socket) }
        .map_err(|error| format!("Failed to register raw TCP socket: {error}"))
}

pub(super) fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "SYN probe deadline expired")
}

pub(super) fn check_deadline(_deadline: tokio::time::Instant) -> io::Result<()> {
    if tokio::time::Instant::now() >= _deadline {
        return Err(timeout_error());
    }
    Ok(())
}

/// One shared readiness path keeps send/receive deadline behavior consistent.
async fn wait_ready(
    _socket: &AsyncFd<Socket>,
    _deadline: tokio::time::Instant,
    _interest: Interest,
) -> io::Result<AsyncFdReadyGuard<'_, Socket>> {
    check_deadline(_deadline)?;
    let guard = tokio::time::timeout_at(_deadline, _socket.ready(_interest))
        .await
        .map_err(|_| timeout_error())??;
    check_deadline(_deadline)?;
    Ok(guard)
}

/// Send the supplied 20-byte TCP header unchanged, whether SYN or RST.
pub(super) async fn send_tcp_header(
    _socket: &AsyncFd<Socket>,
    _header: &[u8; 20],
    _destination_ip: Ipv4Addr,
    _deadline: tokio::time::Instant,
) -> io::Result<()> {
    let destination = SockAddr::from(SocketAddr::from((_destination_ip, 0)));
    loop {
        let mut guard = wait_ready(_socket, _deadline, Interest::WRITABLE).await?;
        match guard.try_io(|socket| socket.get_ref().send_to(_header, &destination)) {
            Ok(Ok(sent)) if sent == _header.len() => return Ok(()),
            Ok(Ok(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Incomplete TCP packet send",
                ));
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

/// Return only initialized bytes of one raw IPv4 packet; parsing is separate.
pub(super) async fn receive_raw_packet(
    _socket: &AsyncFd<Socket>,
    _deadline: tokio::time::Instant,
) -> io::Result<Vec<u8>> {
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 65_535];
    loop {
        let mut guard = wait_ready(_socket, _deadline, Interest::READABLE).await?;
        match guard.try_io(|socket| socket.get_ref().recv(&mut buffer)) {
            Ok(Ok(received)) => {
                let bytes = buffer[..received]
                    .iter()
                    .map(|byte| {
                        // SAFETY: successful recv initialized exactly this prefix.
                        unsafe { byte.assume_init() }
                    })
                    .collect();
                return Ok(bytes);
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}
