//! IPv4 address validation.
//!
//! Every address the resolver learns from DNS must be a globally routable
//! unicast IPv4 address. Anything in a special-purpose range (RFC 6890 and
//! friends) is rejected so that a compromised or misconfigured zone can never
//! turn the production HTTPS rule into access to loopback, link-local (GCP
//! metadata), private networks, the Prometheus proxy, multicast or reserved
//! space.

use std::net::Ipv4Addr;

/// Special-purpose IPv4 ranges that are never valid egress targets.
///
/// Each entry is `(network, prefix_len)`.
const SPECIAL_RANGES: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),       // "this" network
    (Ipv4Addr::new(10, 0, 0, 0), 8),      // private
    (Ipv4Addr::new(100, 64, 0, 0), 10),   // shared address space (CGNAT)
    (Ipv4Addr::new(127, 0, 0, 0), 8),     // loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16),  // link-local (cloud metadata lives here)
    (Ipv4Addr::new(172, 16, 0, 0), 12),   // private
    (Ipv4Addr::new(192, 0, 0, 0), 24),    // IETF protocol assignments
    (Ipv4Addr::new(192, 0, 2, 0), 24),    // TEST-NET-1
    (Ipv4Addr::new(192, 88, 99, 0), 24),  // 6to4 relay anycast (deprecated)
    (Ipv4Addr::new(192, 168, 0, 0), 16),  // private
    (Ipv4Addr::new(198, 18, 0, 0), 15),   // benchmarking
    (Ipv4Addr::new(198, 51, 100, 0), 24), // TEST-NET-2
    (Ipv4Addr::new(203, 0, 113, 0), 24),  // TEST-NET-3
    (Ipv4Addr::new(224, 0, 0, 0), 4),     // multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),     // reserved + broadcast
];

/// Returns `true` if `ip` is a globally routable unicast address.
pub fn is_global_unicast(ip: Ipv4Addr) -> bool {
    !SPECIAL_RANGES
        .iter()
        .any(|(net, len)| in_range(ip, *net, *len))
}

fn in_range(ip: Ipv4Addr, net: Ipv4Addr, prefix_len: u8) -> bool {
    debug_assert!(prefix_len <= 32);
    if prefix_len == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - u32::from(prefix_len));
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn accepts_current_buildernet_addresses() {
        for a in [
            "200.225.47.181",
            "200.225.47.183",
            "198.203.202.53",
            "198.203.202.55",
            "34.104.157.101",
            "35.213.62.127",
            "198.203.203.37",
            "1.1.1.1",
            "8.8.8.8",
        ] {
            assert!(is_global_unicast(ip(a)), "{a} should be accepted");
        }
    }

    #[test]
    fn rejects_special_purpose_ranges() {
        for a in [
            "0.0.0.0",
            "0.1.2.3",
            "10.88.0.100", // Prometheus proxy
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.0.0.53",
            "169.254.169.254", // GCP metadata
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_global_unicast(ip(a)), "{a} should be rejected");
        }
    }

    #[test]
    fn range_boundaries_are_exact() {
        // 100.64.0.0/10 ends at 100.127.255.255
        assert!(!is_global_unicast(ip("100.127.255.255")));
        assert!(is_global_unicast(ip("100.128.0.0")));
        assert!(is_global_unicast(ip("100.63.255.255")));
        // 172.16.0.0/12 ends at 172.31.255.255
        assert!(is_global_unicast(ip("172.32.0.0")));
        assert!(is_global_unicast(ip("172.15.255.255")));
        // 198.18.0.0/15 ends at 198.19.255.255
        assert!(is_global_unicast(ip("198.20.0.0")));
        assert!(is_global_unicast(ip("198.17.255.255")));
        // 198.203.x.x (BuilderNet EU/AP) must not be caught by the benchmarking range
        assert!(is_global_unicast(ip("198.203.202.53")));
    }
}
