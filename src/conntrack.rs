//! Connection hygiene.
//!
//! The host firewall accepts ESTABLISHED flows before the mode chains are
//! consulted, so a flow that was allowed once survives any later rule change
//! until its conntrack entry is deleted. Instead of remembering diffs (which a
//! crash between "apply" and "kill" would lose), every run derives the set of
//! flows that must not exist from the *current* mode and chain contents and
//! deletes them. The operation is idempotent.

use std::net::Ipv4Addr;

use crate::exec::Exec;
use crate::iptables::AddrMap;

pub const CONNTRACK: &str = "/usr/sbin/conntrack";

/// Addresses whose TCP flows to `port` must not exist right now.
///
/// * production: every address in the maintenance (seen) set that is not in
///   the production (allowed) set — i.e. retired addresses;
/// * any other mode: every address ever resolved.
pub fn kill_set(mode: &str, production: &AddrMap, maintenance: &AddrMap) -> Vec<Ipv4Addr> {
    maintenance
        .keys()
        .filter(|ip| mode != "production" || !production.contains_key(ip))
        .copied()
        .collect()
}

/// Delete conntrack entries for TCP flows to each `ip:port`.
///
/// Returns the addresses whose deletion command failed. `conntrack -D` exits 1
/// when nothing matched, which is not a failure here.
pub fn kill(exec: &mut dyn Exec, port: u16, ips: &[Ipv4Addr]) -> Vec<(Ipv4Addr, String)> {
    let port = port.to_string();
    let mut failed = Vec::new();
    for ip in ips {
        let dst = ip.to_string();
        match exec.run(
            CONNTRACK,
            &["-D", "-p", "tcp", "-d", &dst, "--dport", &port],
            None,
        ) {
            Ok(out) if out.status == 0 || out.status == 1 => {}
            Ok(out) => failed.push((*ip, format!("status {}: {}", out.status, out.stderr.trim()))),
            Err(e) => failed.push((*ip, e.to_string())),
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::fake::FakeExec;
    use std::collections::BTreeSet;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn map(ips: &[&str]) -> AddrMap {
        ips.iter().map(|s| (ip(s), BTreeSet::new())).collect()
    }

    #[test]
    fn production_kills_only_retired_addresses() {
        let prod = map(&["200.225.47.181", "35.213.62.127"]);
        let maint = map(&["200.225.47.181", "35.213.62.127", "198.203.203.37"]);
        assert_eq!(kill_set("production", &prod, &maint), vec![ip("198.203.203.37")]);
    }

    #[test]
    fn maintenance_and_stopped_kill_everything_seen() {
        let prod = map(&["200.225.47.181"]);
        let maint = map(&["200.225.47.181", "198.203.203.37"]);
        let expected = vec![ip("198.203.203.37"), ip("200.225.47.181")];
        assert_eq!(kill_set("maintenance", &prod, &maint), expected);
        assert_eq!(kill_set("stopped", &prod, &maint), expected);
        assert_eq!(kill_set("", &prod, &maint), expected);
    }

    #[test]
    fn kill_runs_one_scoped_delete_per_address_and_tolerates_no_match() {
        let mut ex = FakeExec::default().respond(1, "0 flow entries have been deleted.").respond(0, "");
        let failed = kill(&mut ex, 443, &[ip("1.1.1.1"), ip("2.2.2.2")]);
        assert!(failed.is_empty());
        assert_eq!(ex.calls.len(), 2);
        assert_eq!(
            ex.calls[0].args,
            vec!["-D", "-p", "tcp", "-d", "1.1.1.1", "--dport", "443"]
        );
    }

    #[test]
    fn kill_reports_real_failures() {
        let mut ex = FakeExec::default().respond(2, "");
        let failed = kill(&mut ex, 443, &[ip("1.1.1.1")]);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, ip("1.1.1.1"));
    }
}
