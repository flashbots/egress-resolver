//! Pure planning logic: merge fresh answers with the current kernel state.
//!
//! * A name that resolved (`Ok`) gets its fresh addresses.
//! * A name with an authenticated negative answer (`Empty`) is cleared.
//! * A name that failed transiently keeps its last-known-good addresses, read
//!   back from the production chain's rule comments.
//! * The production set is the union over all names; the maintenance set is the
//!   union of the current maintenance chain and the new production set, so it
//!   only ever grows while the box is up.
//! * If the production set would exceed `max_addresses`, the previous chain is
//!   kept and an error is recorded.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::answers::{Answers, Outcome};
use crate::config::Config;
use crate::iptables::{entries_to_map, AddrMap, RuleEntry};
use crate::validate::is_global_unicast;

/// Where a name's addresses in the plan came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Fresh authenticated answer.
    Fresh,
    /// Transient failure; previous addresses retained from the kernel.
    LastKnownGood,
    /// Authenticated negative answer; name intentionally has no addresses.
    Empty,
    /// Transient failure and nothing previously known.
    Missing,
}

#[derive(Debug, Clone, Serialize)]
pub struct NameState {
    pub name: String,
    pub required: bool,
    pub outcome: Outcome,
    pub source: Source,
    pub addrs: Vec<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub names: Vec<NameState>,
    pub production: AddrMap,
    pub maintenance: AddrMap,
    pub added: Vec<Ipv4Addr>,
    pub removed: Vec<Ipv4Addr>,
    /// Set when the production chain was deliberately left unchanged.
    pub error: Option<String>,
}

impl Plan {
    /// True when every `required` endpoint has at least one address.
    pub fn required_satisfied(&self) -> bool {
        self.names
            .iter()
            .filter(|n| n.required)
            .all(|n| !n.addrs.is_empty())
    }
}

pub fn compute(
    cfg: &Config,
    answers: &Answers,
    current_production: &[RuleEntry],
    current_maintenance: &[RuleEntry],
) -> Plan {
    let current_prod_map = entries_to_map(current_production);
    let mut names = Vec::with_capacity(cfg.endpoints.len());

    for (ep, name) in cfg.endpoints.iter().zip(cfg.endpoint_names()) {
        let previous: Vec<Ipv4Addr> = current_prod_map
            .iter()
            .filter(|(_, ns)| ns.contains(&name))
            .map(|(ip, _)| *ip)
            .collect();

        let state = match answers.find(&name) {
            Some(r) if r.outcome == Outcome::Ok => {
                let invalid: Vec<_> = r
                    .addrs
                    .iter()
                    .filter(|ip| !is_global_unicast(**ip))
                    .collect();
                if r.addrs.is_empty() {
                    lkg(&name, ep.required, previous, "ok outcome without addresses".into())
                } else if !invalid.is_empty() {
                    lkg(
                        &name,
                        ep.required,
                        previous,
                        format!("answer contains non-global address(es): {invalid:?}"),
                    )
                } else {
                    let mut seen = BTreeSet::new();
                    let addrs = r
                        .addrs
                        .iter()
                        .copied()
                        .filter(|ip| seen.insert(*ip))
                        .collect();
                    NameState {
                        name: name.clone(),
                        required: ep.required,
                        outcome: Outcome::Ok,
                        source: Source::Fresh,
                        addrs,
                        error: None,
                    }
                }
            }
            Some(r) if r.outcome == Outcome::Empty => NameState {
                name: name.clone(),
                required: ep.required,
                outcome: Outcome::Empty,
                source: Source::Empty,
                addrs: Vec::new(),
                error: r.error.clone(),
            },
            Some(r) => lkg(
                &name,
                ep.required,
                previous,
                r.error.clone().unwrap_or_else(|| "transient failure".into()),
            ),
            None => lkg(&name, ep.required, previous, "no result for name".into()),
        };
        names.push(state);
    }

    let mut production = AddrMap::new();
    for n in &names {
        for ip in &n.addrs {
            production.entry(*ip).or_default().insert(n.name.clone());
        }
    }

    let mut error = None;
    if production.len() > cfg.firewall.max_addresses {
        error = Some(format!(
            "resolved {} addresses, more than max_addresses={}; keeping previous chain",
            production.len(),
            cfg.firewall.max_addresses
        ));
        production = current_prod_map.clone();
    }

    let mut maintenance = entries_to_map(current_maintenance);
    for (ip, ns) in &production {
        maintenance.entry(*ip).or_default().extend(ns.iter().cloned());
    }

    let added = production
        .keys()
        .filter(|ip| !current_prod_map.contains_key(ip))
        .copied()
        .collect();
    let removed = current_prod_map
        .keys()
        .filter(|ip| !production.contains_key(ip))
        .copied()
        .collect();

    Plan {
        names,
        production,
        maintenance,
        added,
        removed,
        error,
    }
}

fn lkg(name: &str, required: bool, previous: Vec<Ipv4Addr>, error: String) -> NameState {
    let source = if previous.is_empty() {
        Source::Missing
    } else {
        Source::LastKnownGood
    };
    NameState {
        name: name.to_string(),
        required,
        outcome: Outcome::Transient,
        source,
        addrs: previous,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answers::NameResult;

    fn cfg() -> Config {
        Config::parse(
            r#"
[resolver]
servers = ["1.1.1.1"]
server_name = "cloudflare-dns.com"
[firewall]
production_chain = "P"
maintenance_chain = "M"
max_addresses = 4
[[endpoint]]
name = "rpc.buildernet.org"
required = true
[[endpoint]]
name = "direct-us.buildernet.org"
[[endpoint]]
name = "direct-ap.buildernet.org"
"#,
        )
        .unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ok(name: &str, addrs: &[&str]) -> NameResult {
        NameResult {
            name: name.into(),
            outcome: Outcome::Ok,
            addrs: addrs.iter().map(|a| ip(a)).collect(),
            min_ttl: Some(300),
            server: Some("1.1.1.1".into()),
            error: None,
        }
    }

    fn transient(name: &str) -> NameResult {
        NameResult {
            name: name.into(),
            outcome: Outcome::Transient,
            addrs: vec![],
            min_ttl: None,
            server: None,
            error: Some("SERVFAIL".into()),
        }
    }

    fn empty(name: &str) -> NameResult {
        NameResult {
            name: name.into(),
            outcome: Outcome::Empty,
            addrs: vec![],
            min_ttl: None,
            server: Some("1.1.1.1".into()),
            error: Some("NXDOMAIN".into()),
        }
    }

    fn answers(results: Vec<NameResult>) -> Answers {
        Answers {
            schema: 1,
            generated_uptime_secs: 100.0,
            results,
        }
    }

    fn entry(ipv4: &str, names: &[&str]) -> RuleEntry {
        RuleEntry {
            ip: ip(ipv4),
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn fresh_answers_build_union_and_maintenance_grows() {
        let a = answers(vec![
            ok("rpc.buildernet.org", &["200.225.47.181", "200.225.47.183"]),
            ok("direct-us.buildernet.org", &["200.225.47.181", "200.225.47.183"]),
            ok("direct-ap.buildernet.org", &["35.213.62.127"]),
        ]);
        let current_maint = vec![entry("198.203.203.37", &["direct-ap.buildernet.org"])];
        let p = compute(&cfg(), &a, &[], &current_maint);
        assert!(p.error.is_none());
        assert_eq!(p.production.len(), 3);
        assert_eq!(
            p.production[&ip("200.225.47.181")],
            ["direct-us.buildernet.org", "rpc.buildernet.org"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
        // retired IP stays dropped; new ones are added
        assert_eq!(p.maintenance.len(), 4);
        assert!(p.maintenance.contains_key(&ip("198.203.203.37")));
        assert_eq!(p.added.len(), 3);
        assert!(p.removed.is_empty());
        assert!(p.required_satisfied());
        assert!(p.names.iter().all(|n| n.source == Source::Fresh));
    }

    #[test]
    fn transient_failure_keeps_last_known_good_per_name() {
        let current_prod = vec![
            entry("200.225.47.181", &["rpc.buildernet.org", "direct-us.buildernet.org"]),
            entry("34.104.157.101", &["direct-ap.buildernet.org"]),
        ];
        let a = answers(vec![
            ok("rpc.buildernet.org", &["200.225.47.181"]),
            ok("direct-us.buildernet.org", &["200.225.47.181"]),
            transient("direct-ap.buildernet.org"),
        ]);
        let p = compute(&cfg(), &a, &current_prod, &current_prod);
        let ap = p.names.iter().find(|n| n.name == "direct-ap.buildernet.org").unwrap();
        assert_eq!(ap.source, Source::LastKnownGood);
        assert_eq!(ap.addrs, vec![ip("34.104.157.101")]);
        assert!(p.production.contains_key(&ip("34.104.157.101")));
        assert!(p.added.is_empty() && p.removed.is_empty());
    }

    #[test]
    fn transient_failure_without_history_is_missing() {
        let a = answers(vec![
            transient("rpc.buildernet.org"),
            ok("direct-us.buildernet.org", &["200.225.47.181"]),
            ok("direct-ap.buildernet.org", &["35.213.62.127"]),
        ]);
        let p = compute(&cfg(), &a, &[], &[]);
        let rpc = p.names.iter().find(|n| n.name == "rpc.buildernet.org").unwrap();
        assert_eq!(rpc.source, Source::Missing);
        assert!(!p.required_satisfied(), "rpc is required and has no address");
        assert_eq!(p.production.len(), 2);
    }

    #[test]
    fn authenticated_negative_clears_name_and_removes_ip() {
        let current_prod = vec![
            entry("200.225.47.181", &["rpc.buildernet.org", "direct-us.buildernet.org"]),
            entry("198.203.203.37", &["direct-ap.buildernet.org"]),
        ];
        let a = answers(vec![
            ok("rpc.buildernet.org", &["200.225.47.181"]),
            ok("direct-us.buildernet.org", &["200.225.47.181"]),
            empty("direct-ap.buildernet.org"),
        ]);
        let p = compute(&cfg(), &a, &current_prod, &current_prod);
        let ap = p.names.iter().find(|n| n.name == "direct-ap.buildernet.org").unwrap();
        assert_eq!(ap.source, Source::Empty);
        assert!(ap.addrs.is_empty());
        assert_eq!(p.removed, vec![ip("198.203.203.37")]);
        // still dropped in maintenance for the rest of the boot
        assert!(p.maintenance.contains_key(&ip("198.203.203.37")));
    }

    #[test]
    fn ip_moving_between_names_is_not_a_removal() {
        let current_prod = vec![entry("200.225.47.181", &["rpc.buildernet.org"])];
        let a = answers(vec![
            ok("rpc.buildernet.org", &["200.225.47.183"]),
            ok("direct-us.buildernet.org", &["200.225.47.181"]),
            ok("direct-ap.buildernet.org", &["35.213.62.127"]),
        ]);
        let p = compute(&cfg(), &a, &current_prod, &current_prod);
        assert!(!p.removed.contains(&ip("200.225.47.181")));
        assert_eq!(p.added, vec![ip("35.213.62.127"), ip("200.225.47.183")]);
    }

    #[test]
    fn non_global_address_fails_the_name_transiently() {
        let current_prod = vec![entry("200.225.47.181", &["rpc.buildernet.org"])];
        let a = answers(vec![
            ok("rpc.buildernet.org", &["200.225.47.183", "169.254.169.254"]),
            ok("direct-us.buildernet.org", &["200.225.47.183"]),
            ok("direct-ap.buildernet.org", &["35.213.62.127"]),
        ]);
        let p = compute(&cfg(), &a, &current_prod, &current_prod);
        let rpc = p.names.iter().find(|n| n.name == "rpc.buildernet.org").unwrap();
        assert_eq!(rpc.source, Source::LastKnownGood);
        assert_eq!(rpc.addrs, vec![ip("200.225.47.181")]);
        assert!(!p.production.contains_key(&ip("169.254.169.254")));
    }

    #[test]
    fn exceeding_max_addresses_keeps_previous_chain() {
        let current_prod = vec![entry("200.225.47.181", &["rpc.buildernet.org"])];
        let a = answers(vec![
            ok("rpc.buildernet.org", &["1.1.1.1", "1.1.1.2", "1.1.1.3"]),
            ok("direct-us.buildernet.org", &["1.1.1.4", "1.1.1.5"]),
            ok("direct-ap.buildernet.org", &["1.1.1.6"]),
        ]);
        let p = compute(&cfg(), &a, &current_prod, &current_prod);
        assert!(p.error.is_some());
        assert_eq!(p.production, entries_to_map(&current_prod));
        assert!(p.added.is_empty() && p.removed.is_empty());
    }

    #[test]
    fn missing_result_for_endpoint_is_transient() {
        let a = answers(vec![ok("rpc.buildernet.org", &["200.225.47.181"])]);
        let p = compute(&cfg(), &a, &[], &[]);
        let us = p.names.iter().find(|n| n.name == "direct-us.buildernet.org").unwrap();
        assert_eq!(us.outcome, Outcome::Transient);
        assert_eq!(us.source, Source::Missing);
    }
}
