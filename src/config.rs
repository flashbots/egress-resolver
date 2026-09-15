//! Configuration file (`/etc/bob/egress-resolver.toml`).
//!
//! The file is part of the measured image. It is the single source of truth
//! for which hostnames may be resolved, which resolver is trusted, which
//! firewall chains are runtime-populated and which static hosts entries the
//! searcher container receives.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::Deserialize;

/// Default location of the configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/bob/egress-resolver.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub resolver: ResolverConfig,
    pub firewall: FirewallConfig,
    #[serde(default, rename = "endpoint")]
    pub endpoints: Vec<Endpoint>,
    #[serde(default, rename = "static_host")]
    pub static_hosts: Vec<StaticHost>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    /// Recursive resolvers, tried in order until one returns a usable answer.
    pub servers: Vec<Ipv4Addr>,
    /// TLS server name the resolver certificate must be valid for.
    pub server_name: String,
    /// DNS-over-TLS port.
    #[serde(default = "default_dot_port")]
    pub port: u16,
    /// Per-query timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Attempts per name per server before moving on.
    #[serde(default = "default_attempts")]
    pub attempts: u32,
    /// Require the AD (authenticated data) bit, i.e. the resolver's DNSSEC
    /// validation, on every accepted answer.
    #[serde(default = "default_true")]
    pub require_authenticated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// Chain jumped to from PRODUCTION_OUT; holds one ACCEPT rule per address.
    pub production_chain: String,
    /// Chain jumped to from MAINTENANCE_OUT; holds one DROP rule per address and
    /// only ever grows while the box is up.
    pub maintenance_chain: String,
    /// Destination TCP port of the production accept rules.
    #[serde(default = "default_https_port")]
    pub port: u16,
    /// Upper bound on the number of addresses in the production chain. A larger
    /// result is treated as an error and the previous chain contents are kept.
    #[serde(default = "default_max_addresses")]
    pub max_addresses: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Hostname to resolve (A records only).
    pub name: String,
    /// When true, `toggle production` is refused while this name has no
    /// address at all.
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticHost {
    pub ip: Ipv4Addr,
    pub names: Vec<String>,
}

fn default_dot_port() -> u16 {
    853
}
fn default_timeout_secs() -> u64 {
    5
}
fn default_attempts() -> u32 {
    3
}
fn default_true() -> bool {
    true
}
fn default_https_port() -> u16 {
    443
}
fn default_max_addresses() -> usize {
    64
}

#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text).map_err(|e| ConfigError(format!("invalid config: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.resolver.servers.is_empty() {
            return Err(ConfigError("resolver.servers must not be empty".into()));
        }
        if self.resolver.server_name.is_empty() {
            return Err(ConfigError("resolver.server_name must not be empty".into()));
        }
        if self.resolver.attempts == 0 {
            return Err(ConfigError("resolver.attempts must be >= 1".into()));
        }
        if self.resolver.timeout_secs == 0 {
            return Err(ConfigError("resolver.timeout_secs must be >= 1".into()));
        }
        if self.endpoints.is_empty() {
            return Err(ConfigError("at least one [[endpoint]] is required".into()));
        }
        if self.firewall.production_chain == self.firewall.maintenance_chain {
            return Err(ConfigError("firewall chains must differ".into()));
        }
        for chain in [&self.firewall.production_chain, &self.firewall.maintenance_chain] {
            if !is_chain_name(chain) {
                return Err(ConfigError(format!("invalid chain name {chain:?}")));
            }
        }
        if self.firewall.max_addresses == 0 {
            return Err(ConfigError("firewall.max_addresses must be >= 1".into()));
        }
        let mut seen = BTreeSet::new();
        for ep in &self.endpoints {
            let name = normalize_name(&ep.name);
            if !is_hostname(&name) {
                return Err(ConfigError(format!("invalid endpoint name {:?}", ep.name)));
            }
            if !seen.insert(name) {
                return Err(ConfigError(format!("duplicate endpoint {:?}", ep.name)));
            }
        }
        for sh in &self.static_hosts {
            if sh.names.is_empty() {
                return Err(ConfigError(format!("static_host {} has no names", sh.ip)));
            }
            for n in &sh.names {
                if !is_hostname(&normalize_name(n)) {
                    return Err(ConfigError(format!("invalid static_host name {n:?}")));
                }
            }
        }
        Ok(())
    }

    /// Endpoint names, normalized (lower-case, no trailing dot), in config order.
    pub fn endpoint_names(&self) -> Vec<String> {
        self.endpoints.iter().map(|e| normalize_name(&e.name)).collect()
    }
}

/// Lower-case a hostname and strip a trailing dot.
pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Conservative hostname check: letters, digits, hyphens, dots; labels 1..=63,
/// total <= 253, no empty labels, labels do not start or end with '-'.
pub fn is_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// iptables chain names: up to 28 chars, no whitespace; we are stricter.
pub fn is_chain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 28
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &str = r#"
[resolver]
servers = ["1.1.1.1", "1.0.0.1"]
server_name = "cloudflare-dns.com"

[firewall]
production_chain = "DYN_BNET_PRODUCTION_OUT"
maintenance_chain = "DYN_BNET_MAINTENANCE_OUT"

[[endpoint]]
name = "rpc.buildernet.org"
required = true

[[endpoint]]
name = "direct-us.buildernet.org"

[[endpoint]]
name = "Direct-EU.buildernet.org."

[[static_host]]
ip = "3.149.14.12"
names = ["tx.tee-searcher.flashbots.net"]
"#;

    #[test]
    fn parses_sample_with_defaults() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(cfg.resolver.port, 853);
        assert_eq!(cfg.resolver.timeout_secs, 5);
        assert_eq!(cfg.resolver.attempts, 3);
        assert!(cfg.resolver.require_authenticated);
        assert_eq!(cfg.firewall.port, 443);
        assert_eq!(cfg.firewall.max_addresses, 64);
        assert_eq!(
            cfg.endpoint_names(),
            vec![
                "rpc.buildernet.org",
                "direct-us.buildernet.org",
                "direct-eu.buildernet.org"
            ]
        );
        assert!(cfg.endpoints[0].required);
        assert!(!cfg.endpoints[1].required);
        assert_eq!(cfg.static_hosts.len(), 1);
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = SAMPLE.replace("required = true", "required = true\nport = 8443");
        assert!(Config::parse(&bad).is_err());
    }

    #[test]
    fn rejects_duplicate_endpoints_case_insensitively() {
        let bad = format!("{SAMPLE}\n[[endpoint]]\nname = \"RPC.buildernet.org\"\n");
        assert!(Config::parse(&bad).is_err());
    }

    #[test]
    fn rejects_empty_servers_and_bad_chain() {
        let bad = SAMPLE.replace(r#"servers = ["1.1.1.1", "1.0.0.1"]"#, "servers = []");
        assert!(Config::parse(&bad).is_err());
        let bad = SAMPLE.replace("DYN_BNET_PRODUCTION_OUT", "has space");
        assert!(Config::parse(&bad).is_err());
        let bad = SAMPLE.replace("DYN_BNET_MAINTENANCE_OUT", "DYN_BNET_PRODUCTION_OUT");
        assert!(Config::parse(&bad).is_err());
    }

    #[test]
    fn hostname_rules() {
        assert!(is_hostname("rpc.buildernet.org"));
        assert!(is_hostname("a-b.example"));
        assert!(!is_hostname(""));
        assert!(!is_hostname("-bad.example"));
        assert!(!is_hostname("bad-.example"));
        assert!(!is_hostname("a..b"));
        assert!(!is_hostname("under_score.example"));
        assert!(!is_hostname(&"a".repeat(64)));
    }
}
