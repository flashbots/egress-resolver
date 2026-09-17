//! `status.json` (consumed by `toggle`) and the Prometheus textfile.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::plan::{NameState, Source};

pub const SCHEMA: u32 = 2;

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub schema: u32,
    /// `/proc/sys/kernel/random/boot_id`, so a reader can detect a stale file
    /// from a previous boot.
    pub boot_id: String,
    /// `/proc/uptime` seconds when this status was written. Readers compare
    /// against the current uptime: monotonic, not host-adjustable.
    pub generated_uptime_secs: f64,
    /// `/proc/uptime` seconds when the DNS answers were produced, if usable.
    pub answers_uptime_secs: Option<f64>,
    /// Content of `/etc/searcher-network.state` at apply time.
    pub mode: String,
    /// The firewall chains hold exactly the planned policy (rewritten, or
    /// confirmed unchanged, and verified by reading them back).
    pub apply_ok: bool,
    /// The container hosts file was written from the installed policy.
    pub hosts_ok: bool,
    /// Every conntrack deletion the sweep attempted succeeded.
    pub conntrack_ok: bool,
    /// Every `required` endpoint has at least one installed address and the
    /// hosts file publishes it. This is what `toggle` gates production on.
    pub required_satisfied: bool,
    /// Every `required` endpoint's addresses come from a fresh authenticated
    /// answer in this run rather than last-known-good.
    pub required_fresh: bool,
    /// Per endpoint name, the `/proc/uptime` seconds of the last run whose
    /// installed addresses came from a fresh authenticated answer. Carried
    /// forward from the previous status of the same boot, so a reader can tell
    /// how long an endpoint has been running on last-known-good addresses.
    /// Absent for a name that has never had a fresh answer this boot.
    pub last_fresh_uptime_secs: BTreeMap<String, f64>,
    pub endpoints: Vec<NameState>,
    pub production: Vec<Ipv4Addr>,
    pub maintenance: Vec<Ipv4Addr>,
    pub added: Vec<Ipv4Addr>,
    pub removed: Vec<Ipv4Addr>,
    /// Destinations whose conntrack entries were deleted successfully.
    pub killed: Vec<Ipv4Addr>,
    /// Destinations whose deletion failed; retried on the next run.
    pub kill_failed: Vec<Ipv4Addr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// The subset of a previous `status.json` that the next run carries forward.
/// Tolerates older and newer schemas: every field defaults.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct PrevStatus {
    #[serde(default)]
    pub boot_id: String,
    #[serde(default)]
    pub answers_uptime_secs: Option<f64>,
    #[serde(default)]
    pub last_fresh_uptime_secs: BTreeMap<String, f64>,
}

impl PrevStatus {
    /// The previous run's status, if the file exists, parses and was written
    /// during this boot. Anything else is ignored: `/run` is a tmpfs, so a
    /// stale file can only come from an unusual setup.
    pub fn load(path: &Path, boot_id: &str) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        let prev: PrevStatus = serde_json::from_str(&text).ok()?;
        (prev.boot_id == boot_id).then_some(prev)
    }
}

impl Status {
    /// True when the whole reconciliation succeeded.
    pub fn all_ok(&self) -> bool {
        self.apply_ok && self.hosts_ok && self.conntrack_ok
    }

    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("status serialises");
        s.push('\n');
        s
    }

    /// Prometheus textfile-collector format.
    ///
    /// Every metric family is emitted exactly once (`# HELP`/`# TYPE` followed
    /// by all its samples); the text-format parser rejects repeated headers.
    pub fn to_metrics(&self) -> String {
        let mut m = String::new();
        let mut family = |name: &str, help: &str, samples: &[(String, f64)]| {
            m.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
            for (labels, value) in samples {
                m.push_str(&format!("{name}{labels} {value}\n"));
            }
        };
        let single = |v: f64| vec![(String::new(), v)];
        family(
            "egress_resolver_last_run_uptime_seconds",
            "System uptime when egress-resolver last ran.",
            &single(self.generated_uptime_secs),
        );
        family(
            "egress_resolver_apply_ok",
            "1 if the firewall chains hold the planned policy.",
            &single(bool_f(self.apply_ok)),
        );
        family(
            "egress_resolver_hosts_ok",
            "1 if the container hosts file was written from the installed policy.",
            &single(bool_f(self.hosts_ok)),
        );
        family(
            "egress_resolver_conntrack_ok",
            "1 if every attempted conntrack deletion succeeded.",
            &single(bool_f(self.conntrack_ok)),
        );
        family(
            "egress_resolver_required_satisfied",
            "1 if every required endpoint has an installed, published address.",
            &single(bool_f(self.required_satisfied)),
        );
        family(
            "egress_resolver_required_fresh",
            "1 if every required endpoint was resolved by a fresh authenticated answer in the last run.",
            &single(bool_f(self.required_fresh)),
        );
        family(
            "egress_resolver_production_addresses",
            "Addresses currently allowed in production mode.",
            &single(self.production.len() as f64),
        );
        family(
            "egress_resolver_maintenance_addresses",
            "Addresses dropped in maintenance mode (seen since boot).",
            &single(self.maintenance.len() as f64),
        );
        family(
            "egress_resolver_kill_failed",
            "Destinations whose conntrack deletion failed in the last run.",
            &single(self.kill_failed.len() as f64),
        );
        family(
            "egress_resolver_errors",
            "Number of errors recorded in the last run.",
            &single(self.errors.len() as f64),
        );
        let modes: Vec<(String, f64)> = ["production", "maintenance", "stopped"]
            .iter()
            .map(|mode| (format!("{{mode=\"{mode}\"}}"), bool_f(self.mode == *mode)))
            .collect();
        family(
            "egress_resolver_mode",
            "Current searcher network mode (1 for the active one).",
            &modes,
        );
        let addrs: Vec<(String, f64)> = self
            .endpoints
            .iter()
            .map(|e| (format!("{{name=\"{}\"}}", e.name), e.addrs.len() as f64))
            .collect();
        family(
            "egress_resolver_endpoint_addresses",
            "Addresses for an endpoint name.",
            &addrs,
        );
        let fresh: Vec<(String, f64)> = self
            .endpoints
            .iter()
            .map(|e| {
                (
                    format!("{{name=\"{}\"}}", e.name),
                    bool_f(matches!(e.source, Source::Fresh | Source::Empty)),
                )
            })
            .collect();
        family(
            "egress_resolver_endpoint_fresh",
            "1 if the endpoint's addresses come from a fresh authenticated answer.",
            &fresh,
        );
        let ages: Vec<(String, f64)> = self
            .last_fresh_uptime_secs
            .iter()
            .map(|(name, t)| {
                (
                    format!("{{name=\"{name}\"}}"),
                    (self.generated_uptime_secs - t).max(0.0),
                )
            })
            .collect();
        family(
            "egress_resolver_endpoint_fresh_age_seconds",
            "Seconds since the endpoint's installed addresses last came from a fresh answer (absent if never this boot).",
            &ages,
        );
        m
    }
}

fn bool_f(b: bool) -> f64 {
    if b {
        1.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answers::Outcome;

    #[test]
    fn metrics_and_json_render() {
        let st = Status {
            schema: SCHEMA,
            boot_id: "b".into(),
            generated_uptime_secs: 12.5,
            answers_uptime_secs: Some(12.0),
            mode: "production".into(),
            apply_ok: true,
            hosts_ok: true,
            conntrack_ok: false,
            required_satisfied: true,
            required_fresh: true,
            last_fresh_uptime_secs: [("rpc.buildernet.org".to_string(), 10.0)]
                .into_iter()
                .collect(),
            endpoints: vec![NameState {
                name: "rpc.buildernet.org".into(),
                required: true,
                outcome: Outcome::Ok,
                source: Source::Fresh,
                addrs: vec!["200.225.47.181".parse().unwrap()],
                error: None,
            }],
            production: vec!["200.225.47.181".parse().unwrap()],
            maintenance: vec!["200.225.47.181".parse().unwrap()],
            added: vec![],
            removed: vec![],
            killed: vec![],
            kill_failed: vec!["198.203.203.37".parse().unwrap()],
            errors: vec!["conntrack -D 198.203.203.37: status 2".into()],
        };
        assert!(!st.all_ok());
        let m = st.to_metrics();
        assert!(m.contains("egress_resolver_mode{mode=\"production\"} 1\n"));
        assert!(m.contains("egress_resolver_mode{mode=\"maintenance\"} 0\n"));
        assert!(m.contains("egress_resolver_endpoint_addresses{name=\"rpc.buildernet.org\"} 1\n"));
        assert!(m.contains("egress_resolver_required_satisfied 1\n"));
        assert!(m.contains("egress_resolver_required_fresh 1\n"));
        assert!(m.contains("egress_resolver_conntrack_ok 0\n"));
        assert!(m.contains("egress_resolver_kill_failed 1\n"));
        assert!(m.contains(
            "egress_resolver_endpoint_fresh_age_seconds{name=\"rpc.buildernet.org\"} 2.5\n"
        ));
        // The text format allows exactly one HELP/TYPE header per metric family;
        // node-exporter drops the whole file otherwise.
        let mut help_names: Vec<&str> = m
            .lines()
            .filter_map(|l| l.strip_prefix("# HELP "))
            .map(|l| l.split(' ').next().unwrap())
            .collect();
        let total = help_names.len();
        help_names.sort_unstable();
        help_names.dedup();
        assert_eq!(help_names.len(), total, "duplicate HELP headers:\n{m}");
        // samples of a family must directly follow its header (no interleaving)
        let mut current = "";
        for line in m.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                current = rest.split(' ').next().unwrap();
            } else if !line.starts_with('#') {
                assert!(
                    line.starts_with(current),
                    "sample {line:?} outside family {current:?}"
                );
            }
        }
        let j = st.to_json();
        assert!(j.contains("\"required_satisfied\": true"));
        assert!(j.contains("\"conntrack_ok\": false"));
        assert!(j.contains("\"kill_failed\""));
        assert!(j.contains("\"errors\""));
        assert!(j.contains("\"last_fresh_uptime_secs\""));
    }

    #[test]
    fn prev_status_loads_only_from_this_boot() {
        let dir = std::env::temp_dir().join(format!("egress-resolver-prev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("status.json");
        std::fs::write(
            &p,
            r#"{"schema":2,"boot_id":"b1","answers_uptime_secs":100.5,"last_fresh_uptime_secs":{"rpc.buildernet.org":99.0},"unknown_future_field":1}"#,
        )
        .unwrap();
        let prev = PrevStatus::load(&p, "b1").unwrap();
        assert_eq!(prev.answers_uptime_secs, Some(100.5));
        assert_eq!(prev.last_fresh_uptime_secs["rpc.buildernet.org"], 99.0);
        assert!(PrevStatus::load(&p, "b2").is_none(), "other boot ignored");
        // older schema without the new fields still loads
        std::fs::write(&p, r#"{"schema":1,"boot_id":"b1"}"#).unwrap();
        let prev = PrevStatus::load(&p, "b1").unwrap();
        assert!(prev.answers_uptime_secs.is_none() && prev.last_fresh_uptime_secs.is_empty());
        std::fs::write(&p, "not json").unwrap();
        assert!(PrevStatus::load(&p, "b1").is_none());
        assert!(PrevStatus::load(&dir.join("missing"), "b1").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
