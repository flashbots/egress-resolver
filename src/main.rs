//! egress-resolver: keep the Flashbox host firewall allowlist and the searcher
//! container's hosts file in sync with an attested list of hostnames.
//!
//! Two steps, meant to run as separate `ExecStart=` lines of one oneshot unit:
//!
//! * `resolve` (unprivileged): DNS-over-TLS queries, writes `answers.json`.
//! * `apply` (CAP_NET_ADMIN): reads `answers.json`, reconciles the two dynamic
//!   iptables chains, the container hosts file, conntrack state, and writes
//!   `status.json` plus a Prometheus textfile.

mod answers;
mod config;
mod conntrack;
mod exec;
mod hosts;
mod iptables;
mod plan;
mod resolve;
mod status;
mod sysutil;
mod validate;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use config::Config;
use exec::SystemExec;

const USAGE: &str = "\
usage: egress-resolver <command> [options]

commands:
  resolve        resolve configured names over DNS-over-TLS, write answers file
  apply          reconcile firewall chains, hosts file and conntrack from answers
  run            resolve, then apply (for manual use)
  check-config   validate the configuration file and print a summary

options (defaults in brackets):
  --config PATH        [/etc/bob/egress-resolver.toml]
  --answers PATH       [/run/egress-resolver/resolve/answers.json]
  --hosts PATH         [/run/flashbox-endpoints/hosts]
  --status PATH        [/run/egress-resolver/status.json]
  --metrics PATH       [/run/egress-resolver/metrics/egress-resolver.prom]
  --state-file PATH    [/etc/searcher-network.state]
  --lock PATH          [/etc/searcher-network.lock]
  --lock-timeout SECS  [30]
";

#[derive(Debug, Clone)]
struct Opts {
    config: PathBuf,
    answers: PathBuf,
    hosts: PathBuf,
    status: PathBuf,
    metrics: PathBuf,
    state_file: PathBuf,
    lock: PathBuf,
    lock_timeout: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            config: PathBuf::from(config::DEFAULT_CONFIG_PATH),
            answers: PathBuf::from("/run/egress-resolver/resolve/answers.json"),
            hosts: PathBuf::from("/run/flashbox-endpoints/hosts"),
            status: PathBuf::from("/run/egress-resolver/status.json"),
            metrics: PathBuf::from("/run/egress-resolver/metrics/egress-resolver.prom"),
            state_file: PathBuf::from("/etc/searcher-network.state"),
            lock: PathBuf::from("/etc/searcher-network.lock"),
            lock_timeout: Duration::from_secs(30),
        }
    }
}

fn parse_args(args: &[String]) -> Result<(String, Opts), String> {
    let mut opts = Opts::default();
    let mut command = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "--config" => opts.config = take(&mut i)?.into(),
            "--answers" => opts.answers = take(&mut i)?.into(),
            "--hosts" => opts.hosts = take(&mut i)?.into(),
            "--status" => opts.status = take(&mut i)?.into(),
            "--metrics" => opts.metrics = take(&mut i)?.into(),
            "--state-file" => opts.state_file = take(&mut i)?.into(),
            "--lock" => opts.lock = take(&mut i)?.into(),
            "--lock-timeout" => {
                let v = take(&mut i)?;
                let secs: u64 = v.parse().map_err(|_| format!("bad --lock-timeout {v:?}"))?;
                opts.lock_timeout = Duration::from_secs(secs);
            }
            "-h" | "--help" => return Err(USAGE.to_string()),
            s if s.starts_with('-') => return Err(format!("unknown option {s}\n\n{USAGE}")),
            s => {
                if command.replace(s.to_string()).is_some() {
                    return Err(format!("unexpected argument {s}\n\n{USAGE}"));
                }
            }
        }
        i += 1;
    }
    let command = command.ok_or_else(|| USAGE.to_string())?;
    Ok((command, opts))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, opts) = match parse_args(&args) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    let result = match command.as_str() {
        "resolve" => cmd_resolve(&opts),
        "apply" => cmd_apply(&opts),
        "run" => cmd_resolve(&opts).and_then(|_| cmd_apply(&opts)),
        "check-config" => cmd_check_config(&opts),
        other => Err(format!("unknown command {other}\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("egress-resolver: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load_config(path: &Path) -> Result<Config, String> {
    Config::load(path).map_err(|e| e.to_string())
}

fn cmd_check_config(opts: &Opts) -> Result<(), String> {
    let cfg = load_config(&opts.config)?;
    println!(
        "ok: {} endpoint(s), {} static host(s), resolvers {:?} via {}:{}, chains {} / {}",
        cfg.endpoints.len(),
        cfg.static_hosts.len(),
        cfg.resolver.servers,
        cfg.resolver.server_name,
        cfg.resolver.port,
        cfg.firewall.production_chain,
        cfg.firewall.maintenance_chain,
    );
    Ok(())
}

fn cmd_resolve(opts: &Opts) -> Result<(), String> {
    let cfg = load_config(&opts.config)?;
    let uptime = sysutil::uptime_secs().map_err(|e| format!("uptime: {e}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let answers = runtime.block_on(resolve::resolve_all(&cfg, uptime));
    drop(runtime);
    let json = serde_json::to_string_pretty(&answers).map_err(|e| e.to_string())? + "\n";
    sysutil::write_atomic(&opts.answers, &json, 0o644)
        .map_err(|e| format!("writing {}: {e}", opts.answers.display()))?;
    let ok = answers.results.iter().filter(|r| r.outcome == answers::Outcome::Ok).count();
    eprintln!(
        "egress-resolver: resolved {ok}/{} name(s); answers written to {}",
        answers.results.len(),
        opts.answers.display()
    );
    Ok(())
}

fn cmd_apply(opts: &Opts) -> Result<(), String> {
    let cfg = load_config(&opts.config)?;
    let mut errors: Vec<String> = Vec::new();

    // Missing or corrupt answers are a transient resolution failure, not a
    // reason to skip reconciliation: keep last-known-good, still sweep flows.
    let (answers, answers_uptime) = match std::fs::read_to_string(&opts.answers)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str::<answers::Answers>(&s).map_err(|e| e.to_string()))
    {
        Ok(a) if a.schema == answers::SCHEMA => {
            let t = a.generated_uptime_secs;
            (a, Some(t))
        }
        Ok(a) => {
            errors.push(format!("answers schema {} unsupported", a.schema));
            (empty_answers(), None)
        }
        Err(e) => {
            errors.push(format!("cannot read answers {}: {e}", opts.answers.display()));
            (empty_answers(), None)
        }
    };

    let mut exec = SystemExec;
    let _lock = sysutil::lock_exclusive(&opts.lock, opts.lock_timeout)
        .map_err(|e| format!("lock {}: {e}", opts.lock.display()))?;

    let current_prod = iptables::read_chain(&mut exec, &cfg.firewall.production_chain)?;
    let current_maint = iptables::read_chain(&mut exec, &cfg.firewall.maintenance_chain)?;

    let plan = plan::compute(&cfg, &answers, &current_prod, &current_maint);
    if let Some(e) = &plan.error {
        errors.push(e.clone());
    }

    let unchanged = plan.production == iptables::entries_to_map(&current_prod)
        && plan.maintenance == iptables::entries_to_map(&current_maint);
    let mut apply_ok = true;
    if unchanged {
        eprintln!("egress-resolver: firewall chains unchanged");
    } else {
        let batch = iptables::render_restore(&cfg.firewall, &plan.production, &plan.maintenance);
        match iptables::apply_restore(&mut exec, &batch) {
            Ok(()) => eprintln!(
                "egress-resolver: firewall updated: +{} -{} (production {}, maintenance {})",
                plan.added.len(),
                plan.removed.len(),
                plan.production.len(),
                plan.maintenance.len()
            ),
            Err(e) => {
                apply_ok = false;
                errors.push(e);
            }
        }
    }

    // Hosts and firewall must agree: only publish the plan's addresses if the
    // chains actually hold them.
    let hosts_names: Vec<plan::NameState> = if apply_ok {
        plan.names.clone()
    } else {
        let live = iptables::entries_to_map(&current_prod);
        plan.names
            .iter()
            .cloned()
            .map(|mut n| {
                n.addrs.retain(|ip| live.contains_key(ip));
                n
            })
            .collect()
    };
    let hosts_text = hosts::render(&cfg.static_hosts, &hosts_names);
    if let Err(e) = sysutil::write_atomic(&opts.hosts, &hosts_text, 0o644) {
        errors.push(format!("writing {}: {e}", opts.hosts.display()));
    }

    let mode = sysutil::read_mode(&opts.state_file);
    let effective_prod = if apply_ok {
        plan.production.clone()
    } else {
        iptables::entries_to_map(&current_prod)
    };
    let effective_maint = if apply_ok {
        plan.maintenance.clone()
    } else {
        iptables::entries_to_map(&current_maint)
    };
    let to_kill = conntrack::kill_set(&mode, &effective_prod, &effective_maint);
    for (ip, e) in conntrack::kill(&mut exec, cfg.firewall.port, &to_kill) {
        errors.push(format!("conntrack -D {ip}: {e}"));
    }

    let st = status::Status {
        schema: status::SCHEMA,
        boot_id: sysutil::boot_id(),
        generated_uptime_secs: sysutil::uptime_secs().unwrap_or(0.0),
        answers_uptime_secs: answers_uptime,
        mode,
        apply_ok,
        required_satisfied: apply_ok && plan.required_satisfied(),
        endpoints: plan.names.clone(),
        production: effective_prod.keys().copied().collect(),
        maintenance: effective_maint.keys().copied().collect(),
        added: if apply_ok { plan.added.clone() } else { Vec::new() },
        removed: if apply_ok { plan.removed.clone() } else { Vec::new() },
        killed: to_kill,
        errors: errors.clone(),
    };
    if let Err(e) = sysutil::write_atomic(&opts.status, &st.to_json(), 0o644) {
        errors.push(format!("writing {}: {e}", opts.status.display()));
    }
    if let Err(e) = sysutil::write_atomic(&opts.metrics, &st.to_metrics(), 0o644) {
        errors.push(format!("writing {}: {e}", opts.metrics.display()));
    }
    for e in &errors {
        eprintln!("egress-resolver: warning: {e}");
    }
    if !apply_ok {
        return Err("firewall apply failed; previous chains kept".into());
    }
    Ok(())
}

fn empty_answers() -> answers::Answers {
    answers::Answers {
        schema: answers::SCHEMA,
        generated_uptime_secs: 0.0,
        results: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_command_and_options() {
        let (cmd, o) = parse_args(&args(&["apply", "--config", "/tmp/c.toml", "--lock-timeout", "5"])).unwrap();
        assert_eq!(cmd, "apply");
        assert_eq!(o.config, PathBuf::from("/tmp/c.toml"));
        assert_eq!(o.lock_timeout, Duration::from_secs(5));
        assert_eq!(o.hosts, PathBuf::from("/run/flashbox-endpoints/hosts"));
    }

    #[test]
    fn rejects_missing_command_and_unknown_option() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["apply", "--bogus"])).is_err());
        assert!(parse_args(&args(&["apply", "resolve"])).is_err());
        assert!(parse_args(&args(&["apply", "--lock-timeout", "x"])).is_err());
    }
}
