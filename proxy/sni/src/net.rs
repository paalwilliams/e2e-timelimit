//! Platform bits: original destination of redirected connections, and IP -> MAC.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

/// Destination the client originally connected to, before an iptables/nftables REDIRECT.
#[cfg(target_os = "linux")]
pub fn original_dst(s: &TcpStream) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsRawFd;
    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
    let fd = s.as_raw_fd();
    unsafe {
        let mut a4: libc::sockaddr_in = std::mem::zeroed();
        let mut l4 = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(fd, libc::SOL_IP, SO_ORIGINAL_DST, &mut a4 as *mut _ as *mut libc::c_void, &mut l4) == 0 {
            let ip = Ipv4Addr::from(u32::from_be(a4.sin_addr.s_addr));
            return Some(SocketAddr::new(ip.into(), u16::from_be(a4.sin_port)));
        }
        let mut a6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut l6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if libc::getsockopt(fd, libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST, &mut a6 as *mut _ as *mut libc::c_void, &mut l6) == 0 {
            let ip = Ipv6Addr::from(a6.sin6_addr.s6_addr);
            return Some(SocketAddr::new(ip.into(), u16::from_be(a6.sin6_port)));
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub fn original_dst(_s: &TcpStream) -> Option<SocketAddr> {
    None // transparent mode needs Linux netfilter
}

/// IP -> MAC from the kernel neighbour table (/proc/net/arp), cached briefly.
pub struct Arp {
    path: String,
    ttl: Duration,
    cache: Mutex<(Option<Instant>, HashMap<String, String>)>,
}

impl Arp {
    pub fn new() -> Self {
        Arp { path: "/proc/net/arp".into(), ttl: Duration::from_secs(30), cache: Mutex::new((None, HashMap::new())) }
    }

    pub fn parse(text: &str) -> HashMap<String, String> {
        text.lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                (f.len() >= 4 && f[3] != "00:00:00:00:00:00").then(|| (f[0].to_string(), f[3].to_lowercase()))
            })
            .collect()
    }

    pub fn lookup(&self, ip: &str) -> Option<String> {
        let mut c = self.cache.lock().unwrap();
        if c.0.map_or(true, |t| t.elapsed() > self.ttl) {
            c.1 = std::fs::read_to_string(&self.path).map(|t| Self::parse(&t)).unwrap_or_default();
            c.0 = Some(Instant::now());
        }
        c.1.get(ip).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_arp() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 192.168.1.20     0x1         0x2         A4:83:E7:12:34:56     *        br-lan\n\
                 192.168.1.21     0x1         0x0         00:00:00:00:00:00     *        br-lan\n";
        let m = Arp::parse(t);
        assert_eq!(m.get("192.168.1.20").map(String::as_str), Some("a4:83:e7:12:34:56"));
        assert!(!m.contains_key("192.168.1.21"));
    }
}
