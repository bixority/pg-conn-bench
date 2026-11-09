//! The kernel's view of one TCP connection (Linux `TCP_INFO`), and the interface that carries it.

use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::RawFd;

/// Per-connection TCP state, read after a phase has finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketSnapshot {
    /// Smoothed round-trip time, in microseconds.
    pub rtt_us: u32,
    /// Round-trip time variance, in microseconds.
    pub rttvar_us: u32,
    /// Segments retransmitted on this connection since it was created, SYNs included.
    pub total_retrans: u32,
    /// Congestion window, in segments.
    pub cwnd: u32,
}

/// Read `TCP_INFO` for an open TCP socket. `None` off Linux or if the call fails.
#[cfg(target_os = "linux")]
pub fn snapshot(fd: RawFd) -> Option<SocketSnapshot> {
    // SAFETY: an all-zero tcp_info is a valid value (plain integers only), and getsockopt writes at
    // most `len` bytes into it. `fd` is only used for the duration of the call.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(SocketSnapshot {
        rtt_us: info.tcpi_rtt,
        rttvar_us: info.tcpi_rttvar,
        total_retrans: info.tcpi_total_retrans,
        cwnd: info.tcpi_snd_cwnd,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn snapshot(_fd: RawFd) -> Option<SocketSnapshot> {
    None
}

/// The local address the kernel would use to reach `remote`. A UDP socket is connected, not
/// written to, so no packet is sent.
pub fn local_ip_for(remote: SocketAddr) -> Option<IpAddr> {
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Name of the interface that has `ip` configured, if any.
#[cfg(target_os = "linux")]
pub fn interface_with_ip(ip: IpAddr) -> Option<String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list that must be released with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut found = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` points into the list returned by getifaddrs, which stays valid until freed.
        let entry = unsafe { &*cur };
        if !entry.ifa_addr.is_null() && sockaddr_ip(entry.ifa_addr) == Some(ip) {
            // SAFETY: ifa_name is a NUL-terminated string owned by the list.
            found = Some(
                unsafe { CStr::from_ptr(entry.ifa_name) }
                    .to_string_lossy()
                    .into_owned(),
            );
            break;
        }
        cur = entry.ifa_next;
    }

    // SAFETY: `head` came from getifaddrs and is freed exactly once, after the last use above.
    unsafe { libc::freeifaddrs(head) };
    found
}

#[cfg(not(target_os = "linux"))]
pub fn interface_with_ip(_ip: IpAddr) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn sockaddr_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    // SAFETY: the caller passes a non-null address from getifaddrs. The family field tells which
    // concrete struct it is.
    unsafe {
        match i32::from((*addr).sa_family) {
            libc::AF_INET => {
                let v4 = &*addr.cast::<libc::sockaddr_in>();
                Some(IpAddr::from(v4.sin_addr.s_addr.to_ne_bytes()))
            }
            libc::AF_INET6 => {
                let v6 = &*addr.cast::<libc::sockaddr_in6>();
                Some(IpAddr::from(v6.sin6_addr.s6_addr))
            }
            _ => None,
        }
    }
}

/// The interface that carries traffic to `remote`, if it can be found.
pub fn route_interface(remote: SocketAddr) -> Option<String> {
    interface_with_ip(local_ip_for(remote)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;

    #[test]
    fn loopback_socket_has_tcp_info() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();

        let s = snapshot(stream.as_raw_fd()).expect("TCP_INFO on a connected socket");

        assert_eq!(
            s.total_retrans, 0,
            "a fresh loopback connection retransmits nothing"
        );
        assert!(s.cwnd > 0);
    }

    #[test]
    fn snapshot_of_a_non_socket_is_none() {
        assert_eq!(snapshot(-1), None);
    }

    #[test]
    fn loopback_route_uses_loopback_address() {
        let remote: SocketAddr = "127.0.0.1:5432".parse().unwrap();
        assert_eq!(local_ip_for(remote), Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn loopback_ip_belongs_to_an_interface() {
        let name = interface_with_ip("127.0.0.1".parse().unwrap());
        assert!(name.is_some(), "loopback should have an interface name");
    }
}
