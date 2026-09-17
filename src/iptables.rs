//! The two runtime-populated iptables chains.
//!
//! `DYN_BNET_PRODUCTION_OUT` holds one `ACCEPT` rule per currently resolved
//! address (`-d IP -p tcp --dport 443 -m conntrack --ctstate NEW`).
//! `DYN_BNET_MAINTENANCE_OUT` holds one `DROP` rule per address ever resolved
//! since boot. Both chains are created empty by `firewall-config` and are
//! statically jumped to from `PRODUCTION_OUT` / `MAINTENANCE_OUT`.
//!
//! Every rule carries `-m comment --comment "<names>"` so the kernel is the
//! single source of truth for which hostname produced which address. That is
//! what makes the tool stateless: last-known-good addresses are read back from
//! the live chain.
//!
//! Both chains are replaced atomically with one `iptables-restore -n` batch
//! (one netlink transaction; other chains untouched).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::config::FirewallConfig;
use crate::exec::Exec;

pub const IPTABLES: &str = "/usr/sbin/iptables";
pub const IPTABLES_RESTORE: &str = "/usr/sbin/iptables-restore";

use crate::config::MAX_COMMENT_LEN;

/// One dynamic rule as read back from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEntry {
    pub ip: Ipv4Addr,
    pub names: BTreeSet<String>,
}

/// Address -> hostnames it was resolved from.
pub type AddrMap = BTreeMap<Ipv4Addr, BTreeSet<String>>;

pub fn entries_to_map(entries: &[RuleEntry]) -> AddrMap {
    let mut m = AddrMap::new();
    for e in entries {
        m.entry(e.ip).or_default().extend(e.names.iter().cloned());
    }
    m
}

/// Parse the output of `iptables -S <chain>` into rule entries.
///
/// Rules without a destination address are ignored; a missing comment yields
/// an empty name set.
pub fn parse_chain(output: &str, chain: &str) -> Vec<RuleEntry> {
    let prefix = format!("-A {chain} ");
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(&prefix)?;
            let toks = tokenize(rest);
            let mut ip = None;
            let mut names = BTreeSet::new();
            let mut i = 0;
            while i < toks.len() {
                match toks[i].as_str() {
                    "-d" if i + 1 < toks.len() => {
                        let dst = toks[i + 1].split('/').next().unwrap_or("");
                        ip = dst.parse::<Ipv4Addr>().ok();
                        i += 2;
                    }
                    "--comment" if i + 1 < toks.len() => {
                        names.extend(toks[i + 1].split_whitespace().map(|s| s.to_string()));
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            ip.map(|ip| RuleEntry { ip, names })
        })
        .collect()
}

/// Split an iptables rule spec into tokens, honouring double quotes and
/// backslash escapes as `iptables -S` prints them.
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut chars = s.chars().peekable();
    let mut have = false;
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quote = !in_quote;
                have = true;
            }
            '\\' if in_quote => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    have = true;
                }
            }
            c if c.is_whitespace() && !in_quote => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            c => {
                cur.push(c);
                have = true;
            }
        }
    }
    if have {
        out.push(cur);
    }
    out
}

fn comment(names: &BTreeSet<String>) -> String {
    let mut c = names.iter().cloned().collect::<Vec<_>>().join(" ");
    if c.len() > MAX_COMMENT_LEN {
        // provenance is informational; keep whole names only
        let mut cut = MAX_COMMENT_LEN;
        while cut > 0 && !c.is_char_boundary(cut) {
            cut -= 1;
        }
        c.truncate(cut);
        if let Some(pos) = c.rfind(' ') {
            c.truncate(pos);
        }
    }
    // names are validated hostnames, so no quotes/backslashes can appear
    c
}

/// Render the `iptables-restore -n` batch that replaces both chains.
pub fn render_restore(fw: &FirewallConfig, production: &AddrMap, maintenance: &AddrMap) -> String {
    let mut s = String::new();
    s.push_str("*filter\n");
    s.push_str(&format!(":{} - [0:0]\n", fw.production_chain));
    s.push_str(&format!(":{} - [0:0]\n", fw.maintenance_chain));
    for (ip, names) in production {
        s.push_str(&format!(
            "-A {chain} -d {ip}/32 -p tcp --dport {port} -m conntrack --ctstate NEW -m comment --comment \"{c}\" -j ACCEPT\n",
            chain = fw.production_chain,
            port = fw.port,
            c = comment(names),
        ));
    }
    for (ip, names) in maintenance {
        s.push_str(&format!(
            "-A {chain} -d {ip}/32 -m comment --comment \"{c}\" -j DROP\n",
            chain = fw.maintenance_chain,
            c = comment(names),
        ));
    }
    s.push_str("COMMIT\n");
    s
}

/// A chain as read back from the kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainRead {
    /// The rules `parse_chain` understood: one destination each.
    pub entries: Vec<RuleEntry>,
    /// Every `-A <chain>` line, including rules `parse_chain` ignored.
    pub rule_lines: usize,
}

impl ChainRead {
    /// True if the chain holds anything but exactly one rule per address: a
    /// rule without a destination (not one of ours) or the same address twice
    /// (a partially applied earlier batch). Such a chain is rewritten even when
    /// its address map already equals the plan.
    pub fn is_dirty(&self) -> bool {
        self.rule_lines != self.entries.len()
            || entries_to_map(&self.entries).len() != self.entries.len()
    }
}

/// Number of `-A <chain>` lines in `iptables -S <chain>` output.
pub fn count_rules(output: &str, chain: &str) -> usize {
    let prefix = format!("-A {chain} ");
    output
        .lines()
        .filter(|l| l.trim().starts_with(&prefix))
        .count()
}

/// Read the current contents of a chain. Fails if the chain does not exist,
/// which means the firewall has not been initialised.
pub fn read_chain(exec: &mut dyn Exec, chain: &str) -> Result<ChainRead, String> {
    let out = exec
        .run(IPTABLES, &["-w", "5", "-S", chain], None)
        .map_err(|e| format!("cannot run {IPTABLES}: {e}"))?;
    if !out.success() {
        return Err(format!(
            "iptables -S {chain} failed (status {}): {}",
            out.status,
            out.stderr.trim()
        ));
    }
    Ok(ChainRead {
        entries: parse_chain(&out.stdout, chain),
        rule_lines: count_rules(&out.stdout, chain),
    })
}

/// Apply a restore batch atomically.
pub fn apply_restore(exec: &mut dyn Exec, batch: &str) -> Result<(), String> {
    let out = exec
        .run(IPTABLES_RESTORE, &["-w", "5", "-n"], Some(batch))
        .map_err(|e| format!("cannot run {IPTABLES_RESTORE}: {e}"))?;
    if !out.success() {
        return Err(format!(
            "iptables-restore failed (status {}): {}",
            out.status,
            out.stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fw() -> FirewallConfig {
        FirewallConfig {
            production_chain: "DYN_BNET_PRODUCTION_OUT".into(),
            maintenance_chain: "DYN_BNET_MAINTENANCE_OUT".into(),
            port: 443,
            max_addresses: 64,
        }
    }

    fn names(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const IPTABLES_S: &str = r#"-N DYN_BNET_PRODUCTION_OUT
-A DYN_BNET_PRODUCTION_OUT -d 200.225.47.181/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -m comment --comment "direct-us.buildernet.org rpc.buildernet.org" -j ACCEPT
-A DYN_BNET_PRODUCTION_OUT -d 35.213.62.127/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -m comment --comment direct-ap.buildernet.org -j ACCEPT
-A DYN_BNET_PRODUCTION_OUT -p tcp -m tcp --dport 443 -j ACCEPT
"#;

    #[test]
    fn parses_iptables_s_output() {
        let entries = parse_chain(IPTABLES_S, "DYN_BNET_PRODUCTION_OUT");
        assert_eq!(entries.len(), 2, "rule without -d is ignored");
        assert_eq!(entries[0].ip, "200.225.47.181".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            entries[0].names,
            names(&["direct-us.buildernet.org", "rpc.buildernet.org"])
        );
        assert_eq!(entries[1].names, names(&["direct-ap.buildernet.org"]));
        assert!(parse_chain(IPTABLES_S, "OTHER").is_empty());
    }

    #[test]
    fn tokenizer_handles_quotes_and_escapes() {
        assert_eq!(
            tokenize(r#"-m comment --comment "a b" -j ACCEPT"#),
            vec!["-m", "comment", "--comment", "a b", "-j", "ACCEPT"]
        );
        assert_eq!(
            tokenize(r#"--comment "say \"hi\"""#),
            vec!["--comment", r#"say "hi""#]
        );
        assert_eq!(tokenize(r#"--comment """#), vec!["--comment", ""]);
    }

    #[test]
    fn renders_restore_batch() {
        let mut prod = AddrMap::new();
        prod.insert(
            "200.225.47.181".parse().unwrap(),
            names(&["rpc.buildernet.org", "direct-us.buildernet.org"]),
        );
        let mut maint = prod.clone();
        maint.insert(
            "198.203.203.37".parse().unwrap(),
            names(&["direct-ap.buildernet.org"]),
        );
        let batch = render_restore(&fw(), &prod, &maint);
        let expected = "*filter\n\
:DYN_BNET_PRODUCTION_OUT - [0:0]\n\
:DYN_BNET_MAINTENANCE_OUT - [0:0]\n\
-A DYN_BNET_PRODUCTION_OUT -d 200.225.47.181/32 -p tcp --dport 443 -m conntrack --ctstate NEW -m comment --comment \"direct-us.buildernet.org rpc.buildernet.org\" -j ACCEPT\n\
-A DYN_BNET_MAINTENANCE_OUT -d 198.203.203.37/32 -m comment --comment \"direct-ap.buildernet.org\" -j DROP\n\
-A DYN_BNET_MAINTENANCE_OUT -d 200.225.47.181/32 -m comment --comment \"direct-us.buildernet.org rpc.buildernet.org\" -j DROP\n\
COMMIT\n";
        assert_eq!(batch, expected);
    }

    #[test]
    fn render_parse_roundtrip() {
        let mut prod = AddrMap::new();
        prod.insert(
            "1.2.3.4".parse().unwrap(),
            names(&["a.example", "b.example"]),
        );
        prod.insert("5.6.7.8".parse().unwrap(), names(&["b.example"]));
        let batch = render_restore(&fw(), &prod, &AddrMap::new());
        // simulate `iptables -S` normalisation of what we wrote
        let listed: String = batch
            .lines()
            .filter(|l| l.starts_with("-A DYN_BNET_PRODUCTION_OUT"))
            .map(|l| l.replace("-p tcp --dport", "-p tcp -m tcp --dport") + "\n")
            .collect();
        let parsed = parse_chain(&listed, "DYN_BNET_PRODUCTION_OUT");
        assert_eq!(entries_to_map(&parsed), prod);
    }

    #[test]
    fn comment_is_bounded() {
        let many: BTreeSet<String> = (0..20)
            .map(|i| format!("{}.buildernet.org", "x".repeat(40 + i)))
            .collect();
        let c = comment(&many);
        assert!(c.len() <= MAX_COMMENT_LEN);
        assert!(!c.ends_with(' '));
        assert!(
            c.split(' ').all(|n| many.contains(n)),
            "only whole names kept"
        );
    }

    #[test]
    fn read_chain_errors_when_chain_missing() {
        use crate::exec::fake::FakeExec;
        let mut ex = FakeExec::default().respond(1, "");
        let err = read_chain(&mut ex, "DYN_BNET_PRODUCTION_OUT").unwrap_err();
        assert!(err.contains("failed"));
        assert_eq!(ex.calls[0].program, IPTABLES);
        assert_eq!(
            ex.calls[0].args,
            vec!["-w", "5", "-S", "DYN_BNET_PRODUCTION_OUT"]
        );
    }

    #[test]
    fn apply_restore_feeds_batch_on_stdin() {
        use crate::exec::fake::FakeExec;
        let mut ex = FakeExec::default().respond(0, "");
        apply_restore(&mut ex, "*filter\nCOMMIT\n").unwrap();
        assert_eq!(ex.calls[0].program, IPTABLES_RESTORE);
        assert_eq!(ex.calls[0].args, vec!["-w", "5", "-n"]);
        assert_eq!(ex.calls[0].stdin.as_deref(), Some("*filter\nCOMMIT\n"));
    }

    #[test]
    fn dirty_chain_detection() {
        let clean = ChainRead {
            entries: parse_chain(IPTABLES_S, "DYN_BNET_PRODUCTION_OUT")
                .into_iter()
                .take(2)
                .collect(),
            rule_lines: 2,
        };
        assert!(!clean.is_dirty());
        // IPTABLES_S has a third rule without -d: foreign, must be cleaned
        let foreign = ChainRead {
            entries: parse_chain(IPTABLES_S, "DYN_BNET_PRODUCTION_OUT"),
            rule_lines: count_rules(IPTABLES_S, "DYN_BNET_PRODUCTION_OUT"),
        };
        assert_eq!(foreign.rule_lines, 3);
        assert!(foreign.is_dirty());
        // the same address twice
        let mut dup = clean.clone();
        dup.entries.push(dup.entries[0].clone());
        dup.rule_lines = 3;
        assert!(dup.is_dirty());
        assert!(!ChainRead::default().is_dirty());
    }
}
