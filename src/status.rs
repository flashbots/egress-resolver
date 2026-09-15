//! `status.json` (consumed by `toggle`) and the Prometheus textfile.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::plan::{NameState, Source};

pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub schema: u32,
    /// `/proc/sys/kernel/random/boot_id`, so a reader can detect a stale file
    /// from a previous boot.
    pub boot_id: String,
    /// `/proc/uptime` seconds when this status was written. Readers compare
    /// against the current uptime: monotonic, not host-adjustable.
    pub generated_uptime_secs: f64,
    /// `/proc/uptime` seconds when the DNS answers were produced.
    pub answers_uptime_secs: Option<f64>,
    /// Content of `/etc/searcher-network.state` at apply time.
    pub mode: String,
    /// True when the firewall chains were (re)written or confirmed unchanged
    /// without error.
    pub apply_ok: bool,
    /// True when every `required` endpoint has at least one address.
    pub required_satisfied: bool,
    pub endpoints: Vec<NameState>,
    pub production: Vec<Ipv4Addr>,
    pub maintenance: Vec<Ipv4Addr>,
    pub added: Vec<Ipv4Addr>,
    pub removed: Vec<Ipv4Addr>,
    pub killed: Vec<Ipv4Addr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl Status {
    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("status serialises");
        s.push('\n');
        s
    }

    /// Prometheus textfile-collector format.
    pub fn to_metrics(&self) -> String {
        let mut m = String::new();
        let mut gauge = |name: &str, help: &str, labels: &str, value: f64| {
            m.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
            m.push_str(&format!("{name}{labels} {value}\n"));
        };
        gauge(
            "egress_resolver_last_run_uptime_seconds",
            "System uptime when egress-resolver last ran.",
            "",
            self.generated_uptime_secs,
        );
        gauge(
            "egress_resolver_apply_ok",
            "1 if the last firewall apply succeeded.",
            "",
            bool_f(self.apply_ok),
        );
        gauge(
            "egress_resolver_required_satisfied",
            "1 if every required endpoint has an address.",
            "",
            bool_f(self.required_satisfied),
        );
        gauge(
            "egress_resolver_production_addresses",
            "Addresses currently allowed in production mode.",
            "",
            self.production.len() as f64,
        );
        gauge(
            "egress_resolver_maintenance_addresses",
            "Addresses dropped in maintenance mode (seen since boot).",
            "",
            self.maintenance.len() as f64,
        );
        gauge(
            "egress_resolver_errors",
            "Number of errors recorded in the last run.",
            "",
            self.errors.len() as f64,
        );
        for mode in ["production", "maintenance", "stopped"] {
            gauge(
                "egress_resolver_mode",
                "Current searcher network mode (1 for the active one).",
                &format!("{{mode=\"{mode}\"}}"),
                bool_f(self.mode == mode),
            );
        }
        m.push_str("# HELP egress_resolver_endpoint_addresses Addresses for an endpoint name.\n# TYPE egress_resolver_endpoint_addresses gauge\n");
        for e in &self.endpoints {
            m.push_str(&format!(
                "egress_resolver_endpoint_addresses{{name=\"{}\"}} {}\n",
                e.name,
                e.addrs.len()
            ));
        }
        m.push_str("# HELP egress_resolver_endpoint_fresh 1 if the endpoint's addresses come from a fresh authenticated answer.\n# TYPE egress_resolver_endpoint_fresh gauge\n");
        for e in &self.endpoints {
            m.push_str(&format!(
                "egress_resolver_endpoint_fresh{{name=\"{}\"}} {}\n",
                e.name,
                bool_f(matches!(e.source, Source::Fresh | Source::Empty))
            ));
        }
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
            required_satisfied: true,
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
            errors: vec![],
        };
        let m = st.to_metrics();
        assert!(m.contains("egress_resolver_mode{mode=\"production\"} 1\n"));
        assert!(m.contains("egress_resolver_mode{mode=\"maintenance\"} 0\n"));
        assert!(m.contains("egress_resolver_endpoint_addresses{name=\"rpc.buildernet.org\"} 1\n"));
        assert!(m.contains("egress_resolver_required_satisfied 1\n"));
        let j = st.to_json();
        assert!(j.contains("\"required_satisfied\": true"));
        assert!(!j.contains("\"errors\""), "empty errors omitted");
    }
}
