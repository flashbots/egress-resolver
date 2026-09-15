//! Hand-off format between the unprivileged `resolve` step and the privileged
//! `apply` step (`/run/egress-resolver/resolve/answers.json`).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answers {
    pub schema: u32,
    /// `/proc/uptime` seconds when the answers were produced.
    pub generated_uptime_secs: f64,
    pub results: Vec<NameResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameResult {
    /// Normalized hostname (lower-case, no trailing dot).
    pub name: String,
    pub outcome: Outcome,
    /// Validated global-unicast IPv4 addresses, resolver order. Empty unless
    /// `outcome == Ok`.
    #[serde(default)]
    pub addrs: Vec<Ipv4Addr>,
    /// Minimum TTL over the accepted A records.
    #[serde(default)]
    pub min_ttl: Option<u32>,
    /// Resolver that produced the accepted answer.
    #[serde(default)]
    pub server: Option<String>,
    /// Human readable reason for `Empty` / `Transient`.
    #[serde(default)]
    pub error: Option<String>,
}

/// Outcome of resolving one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Authenticated answer with at least one valid A record.
    Ok,
    /// Authenticated proof that the name has no A records (NODATA or
    /// NXDOMAIN). The name's addresses must be cleared.
    Empty,
    /// No usable answer (SERVFAIL, timeout, TLS failure, missing AD bit,
    /// address outside the allowed ranges, ...). The previous addresses are
    /// kept.
    Transient,
}

impl Answers {
    pub fn find(&self, name: &str) -> Option<&NameResult> {
        self.results.iter().find(|r| r.name == name)
    }
}
