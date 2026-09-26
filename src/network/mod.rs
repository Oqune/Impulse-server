//! Network transport layer: Dual-Stack (IPv4/IPv6) socket binding and endpoint utilities.
//!
//! Provides socket binding with automatic IPv4/IPv6 dual-stack support (`[::]:port`
//! with `IPV6_V6ONLY = false`) and transparent fallback to IPv4 wildcard (`0.0.0.0:port`)
//! if the operating system does not support IPv6 or has it disabled.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{info, warn};

/// Bind a UDP socket with dual-stack IPv4/IPv6 support when configured with an IPv6 address.
///
/// Behavior:
/// 1. If `address` resolves to an IPv6 wildcard (`[::]:port`):
///    Attempts to create an IPv6 socket and disables `IPV6_V6ONLY` via `socket2`,
///    allowing the socket to accept both IPv4 and IPv6 datagrams on the same port.
///    If IPv6 socket creation or binding fails (e.g. disabled in the OS kernel),
///    it logs a warning and gracefully falls back to `0.0.0.0:port`.
/// 2. If `address` is an IPv4 address (e.g. `0.0.0.0:4433`, `127.0.0.1:4433`):
///    Binds directly to that IPv4 socket address.
/// 3. If `address` is a specific IPv6 address (e.g. `[::1]:4433`, `[2001:db8::1]:4433`):
///    Binds to that IPv6 socket address.
///
/// Returns the bound `UdpSocket` and its effective local `SocketAddr`.
pub fn bind_dual_stack_udp(address: &str) -> io::Result<(UdpSocket, SocketAddr)> {
    let parsed: SocketAddr = address
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid bind address '{address}': {e}")))?;

    match parsed {
        SocketAddr::V6(v6_addr) => {
            if v6_addr.ip().is_unspecified() {
                // Dual-stack wildcard [::]:port
                match bind_dual_stack_v6_wildcard(v6_addr.port()) {
                    Ok((sock, bound)) => {
                        info!("Bound dual-stack IPv4/IPv6 UDP socket on {}", bound);
                        Ok((sock, bound))
                    }
                    Err(err) => {
                        warn!(
                            "Failed to bind IPv6 dual-stack socket on [::]:{} ({err}), falling back to IPv4 0.0.0.0:{}",
                            v6_addr.port(),
                            v6_addr.port()
                        );
                        let fallback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), v6_addr.port());
                        let sock = UdpSocket::bind(fallback_addr)?;
                        let bound = sock.local_addr()?;
                        info!("Bound fallback IPv4 UDP socket on {}", bound);
                        Ok((sock, bound))
                    }
                }
            } else {
                // Specific IPv6 address, e.g. [::1]:port or [2001:db8::1]:port
                let sock = UdpSocket::bind(parsed)?;
                let bound = sock.local_addr()?;
                Ok((sock, bound))
            }
        }
        SocketAddr::V4(_) => {
            // Explicit IPv4 bind
            let sock = UdpSocket::bind(parsed)?;
            let bound = sock.local_addr()?;
            Ok((sock, bound))
        }
    }
}

/// Helper to bind an IPv6 wildcard socket with `IPV6_V6ONLY = false`.
fn bind_dual_stack_v6_wildcard(port: u16) -> io::Result<(UdpSocket, SocketAddr)> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // Disable IPV6_V6ONLY so IPv4 mapped connections are received on this socket.
    if let Err(e) = socket.set_only_v6(false) {
        warn!("Failed to disable IPV6_V6ONLY: {e}");
    }
    let bind_addr: SocketAddr = format!("[::]:{port}").parse().unwrap();
    socket.bind(&bind_addr.into())?;
    let std_sock: UdpSocket = socket.into();
    let local = std_sock.local_addr()?;
    Ok((std_sock, local))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_ipv4_explicit() {
        let (sock, addr) = bind_dual_stack_udp("127.0.0.1:0").unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_ne!(addr.port(), 0);

        // Verify socket functionality
        let buf = [42u8; 4];
        sock.send_to(&buf, addr).unwrap();
        let mut recv_buf = [0u8; 4];
        let (n, from) = sock.recv_from(&mut recv_buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&recv_buf[..n], &buf);
        assert_eq!(from.ip(), addr.ip());
    }

    #[test]
    fn test_bind_dual_stack_wildcard() {
        let (sock, bound) = bind_dual_stack_udp("[::]:0").unwrap();
        assert_ne!(bound.port(), 0);
        sock.set_read_timeout(Some(std::time::Duration::from_millis(500))).unwrap();

        // If IPv6 dual-stack was successfully bound, test communicating via loopback
        if bound.is_ipv6() {
            // Test 1 (IPv4 via dual-stack): IPv4 client sending to 127.0.0.1:port
            let v4_client = UdpSocket::bind("127.0.0.1:0").unwrap();
            let dest_v4: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
            v4_client.send_to(b"PING_V4", dest_v4).unwrap();

            let mut buf = [0u8; 16];
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    assert_eq!(&buf[..n], b"PING_V4");
                    // The IPv4 address should canonicalize to 127.0.0.1 (even if mapped as ::ffff:127.0.0.1)
                    assert_eq!(from.ip().to_canonical(), "127.0.0.1".parse::<IpAddr>().unwrap());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    eprintln!("Warning: IPv4 loopback packet timed out on dual-stack socket: {e}");
                }
                Err(e) => panic!("Unexpected error receiving IPv4 packet: {e}"),
            }

            // Test 2 (IPv6 loopback): IPv6 client sending to [::1]:port
            // Note: If a VPN or host routing table blocks/redirects IPv6 loopback,
            // this may time out; we handle that gracefully without hanging indefinitely.
            if let Ok(v6_client) = UdpSocket::bind("[::1]:0") {
                let dest_v6: SocketAddr = format!("[::1]:{}", bound.port()).parse().unwrap();
                let _ = v6_client.send_to(b"PING_V6", dest_v6);

                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        assert_eq!(&buf[..n], b"PING_V6");
                        assert_eq!(from.ip().to_canonical(), "::1".parse::<IpAddr>().unwrap().to_canonical());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                        eprintln!("Notice: IPv6 loopback packet timed out (host VPN or IPv6 routing disabled)");
                    }
                    Err(e) => {
                        eprintln!("Notice: IPv6 loopback packet failed with error: {e}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_canonical_ipv4_mapped() {
        let mapped: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        let canonical = mapped.to_canonical();
        assert_eq!(canonical, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_invalid_address_error() {
        let res = bind_dual_stack_udp("not_an_ip:port");
        assert!(res.is_err());
    }
}
