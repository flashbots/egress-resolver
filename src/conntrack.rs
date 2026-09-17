//! Connection hygiene.
//!
//! The host firewall accepts ESTABLISHED flows before the mode chains are
//! consulted, so a flow that was allowed once survives any later rule change
//! until its conntrack entry is deleted. Instead of remembering diffs (which a
//! crash between "apply" and "kill" would lose), every run derives the set of
//! flows that must not exist from the *current* mode and chain contents and
//! deletes them. The operation is idempotent.

use std::net::Ipv4Addr;

use crate::exec::{Exec, Output};
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

/// Delete every conntrack entry whose destination is one of `ips`.
///
/// Destination-only, like `toggle`'s own teardown: the maintenance drop rules
/// are port-agnostic, so the sweep must be too. Returns the addresses whose
/// deletion command failed.
///
/// `conntrack -D` exits 1 both when nothing matched and on operational errors
/// (missing kernel support, netlink failures). Only the former is a success
/// here, so exit 1 is accepted solely when the tool printed its `0 flow
/// entries have been deleted` summary (locale is pinned to C by `Exec`).
pub fn kill(exec: &mut dyn Exec, ips: &[Ipv4Addr]) -> Vec<(Ipv4Addr, String)> {
    let mut failed = Vec::new();
    for ip in ips {
        let dst = ip.to_string();
        match exec.run(CONNTRACK, &["-D", "-d", &dst], None) {
            Ok(out) if out.status == 0 => {}
            Ok(out) if out.status == 1 && deleted_nothing(&out) => {}
            Ok(out) => failed.push((*ip, format!("status {}: {}", out.status, out.stderr.trim()))),
            Err(e) => failed.push((*ip, e.to_string())),
        }
    }
    failed
}

const NO_MATCH_SUMMARY: &str = "0 flow entries have been deleted";

/// True if the tool's summary line reports that nothing was deleted. The
/// summary goes to stderr; stdout is checked too in case that ever changes.
fn deleted_nothing(out: &Output) -> bool {
    out.stderr.contains(NO_MATCH_SUMMARY) || out.stdout.contains(NO_MATCH_SUMMARY)
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
        assert_eq!(
            kill_set("production", &prod, &maint),
            vec![ip("198.203.203.37")]
        );
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
    fn kill_runs_one_destination_delete_per_address_and_tolerates_no_match() {
        let mut ex = FakeExec::default()
            .respond_stderr(
                1,
                "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n",
            )
            .respond_stderr(
                0,
                "conntrack v1.4.8 (conntrack-tools): 2 flow entries have been deleted.\n",
            );
        let failed = kill(&mut ex, &[ip("1.1.1.1"), ip("2.2.2.2")]);
        assert!(failed.is_empty(), "{failed:?}");
        assert_eq!(ex.calls.len(), 2);
        assert_eq!(ex.calls[0].args, vec!["-D", "-d", "1.1.1.1"]);
    }

    #[test]
    fn kill_treats_exit_1_without_no_match_summary_as_failure() {
        // conntrack exits 1 for operational errors too
        let mut ex = FakeExec::default()
            .respond_stderr(
                1,
                "conntrack v1.4.8 (conntrack-tools): Operation failed: No such file or directory\n",
            )
            .respond(1, "");
        let failed = kill(&mut ex, &[ip("1.1.1.1"), ip("2.2.2.2")]);
        assert_eq!(failed.len(), 2, "{failed:?}");
        assert!(failed[0].1.contains("Operation failed"));
    }

    #[test]
    fn kill_reports_other_exit_codes_as_failures() {
        let mut ex = FakeExec::default().respond(2, "");
        let failed = kill(&mut ex, &[ip("1.1.1.1")]);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, ip("1.1.1.1"));
    }
}
