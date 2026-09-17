//! egress-resolver: keep the Flashbox host firewall allowlist and the searcher
//! container's hosts file in sync with an attested list of hostnames.
//!
//! Two steps, meant to run as two systemd oneshot units:
//!
//! * `resolve` (unprivileged): DNS-over-TLS queries, writes `answers.json`.
//! * `apply` (CAP_NET_ADMIN, no network): reads `answers.json`, reconciles the
//!   two dynamic iptables chains, the container hosts file and conntrack state,
//!   and writes `status.json` plus a Prometheus textfile.

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
use exec::{Exec, SystemExec};
use iptables::entries_to_map;

/// Answers older than this (in uptime seconds) are ignored by `apply`: they
/// belong to a resolve run that is no longer current, so treating them as
/// fresh would re-publish stale data as if it had just been validated. Three
/// timer intervals.
const ANSWERS_MAX_AGE_SECS: f64 = 180.0;

const USAGE: &str = "\
usage: egress-resolver <command> [options]

commands:
  resolve        resolve configured names over DNS-over-TLS, write answers file
  apply          reconcile firewall chains, hosts file and conntrack from answers
  run            resolve, then apply (for manual use)
  check-config   validate the configuration file and print a summary
  print-servers  print the configured resolver addresses, comma-separated

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
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
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
        "print-servers" => load_config(&opts.config).map(|cfg| println!("{}", cfg.servers_csv())),
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
        "ok: {} endpoint(s), {} static host(s), resolvers {} via {}:{} (deadline {}s), chains {} / {}",
        cfg.endpoints.len(),
        cfg.static_hosts.len(),
        cfg.servers_csv(),
        cfg.resolver.server_name,
        cfg.resolver.port,
        cfg.resolver.deadline_secs,
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
    let ok = answers
        .results
        .iter()
        .filter(|r| r.outcome == answers::Outcome::Ok)
        .count();
    eprintln!(
        "egress-resolver: resolved {ok}/{} name(s); answers written to {}",
        answers.results.len(),
        opts.answers.display()
    );
    Ok(())
}

fn cmd_apply(opts: &Opts) -> Result<(), String> {
    let cfg = load_config(&opts.config)?;
    let now = sysutil::uptime_secs().map_err(|e| format!("uptime: {e}"))?;
    let mut exec = SystemExec;
    let st = run_apply(&cfg, opts, &mut exec, now)?;
    for e in &st.errors {
        eprintln!("egress-resolver: warning: {e}");
    }
    if st.all_ok() {
        Ok(())
    } else {
        Err(format!(
            "reconciliation incomplete (apply_ok={}, hosts_ok={}, conntrack_ok={})",
            st.apply_ok, st.hosts_ok, st.conntrack_ok
        ))
    }
}

/// Read the answers file. Missing, corrupt, foreign-schema or stale answers are
/// reported as an error and treated like a failed resolution (every name keeps
/// its last-known-good addresses).
fn load_answers(
    path: &Path,
    now_uptime: f64,
    already_applied_uptime: Option<f64>,
    errors: &mut Vec<String>,
) -> (answers::Answers, Option<f64>) {
    let parsed = read_answers_file(path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str::<answers::Answers>(&s).map_err(|e| e.to_string()));
    match parsed {
        Ok(a) if a.schema != answers::SCHEMA => {
            errors.push(format!("answers schema {} unsupported", a.schema));
        }
        Ok(a) if now_uptime - a.generated_uptime_secs > ANSWERS_MAX_AGE_SECS => {
            errors.push(format!(
                "answers are {:.0}s old (limit {ANSWERS_MAX_AGE_SECS:.0}s); treating resolution as failed",
                now_uptime - a.generated_uptime_secs
            ));
        }
        Ok(a) if Some(a.generated_uptime_secs) == already_applied_uptime => {
            // The resolve step did not produce a new file since the previous
            // run (it died, or apply was started on its own): nothing here is
            // fresh, however recent the file looks.
            errors.push(format!(
                "answers generated at uptime {:.0}s were already applied by the previous run; treating resolution as failed",
                a.generated_uptime_secs
            ));
        }
        Ok(a) => {
            let t = a.generated_uptime_secs;
            return (a, Some(t));
        }
        Err(e) => errors.push(format!("cannot read answers {}: {e}", path.display())),
    }
    (
        answers::Answers {
            schema: answers::SCHEMA,
            generated_uptime_secs: 0.0,
            results: Vec::new(),
        },
        None,
    )
}

/// Read the answers file without following a symlink: it lives in a directory
/// owned by the unprivileged resolve step and is read here as root.
fn read_answers_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}

/// One reconciliation pass: read the answers and the kernel, compute the plan,
/// rewrite the chains if needed, publish hosts, sweep conntrack, write status.
fn run_apply(
    cfg: &Config,
    opts: &Opts,
    exec: &mut dyn Exec,
    now_uptime: f64,
) -> Result<status::Status, String> {
    let mut errors: Vec<String> = Vec::new();
    let boot_id = sysutil::boot_id();
    let prev = status::PrevStatus::load(&opts.status, &boot_id).unwrap_or_default();
    let (answers, answers_uptime) = load_answers(
        &opts.answers,
        now_uptime,
        prev.applied_answers_uptime_secs,
        &mut errors,
    );
    // Generation time of the answers most recently applied. Carried forward
    // when this run applied none, so a file that stops changing is rejected
    // on every following run, not just the first.
    let applied_answers_uptime_secs = answers_uptime.or(prev.applied_answers_uptime_secs);

    let _lock = sysutil::lock_exclusive(&opts.lock, opts.lock_timeout)
        .map_err(|e| format!("lock {}: {e}", opts.lock.display()))?;

    let current_prod = iptables::read_chain(exec, &cfg.firewall.production_chain)?;
    let current_maint = iptables::read_chain(exec, &cfg.firewall.maintenance_chain)?;
    let current_prod_map = entries_to_map(&current_prod.entries);
    let current_maint_map = entries_to_map(&current_maint.entries);

    let plan = plan::compute(cfg, &answers, &current_prod.entries, &current_maint.entries);
    if let Some(e) = &plan.error {
        errors.push(e.clone());
    }

    // 1. Firewall. Rewrite both chains only if the plan differs or a chain
    //    holds something other than one rule per address (a duplicate from an
    //    interrupted earlier batch, a rule that is not ours), then read the
    //    kernel back: the chains must hold exactly the plan (same rules, same
    //    count), otherwise the update is treated as failed.
    let mut apply_ok = true;
    let dirty = current_prod.is_dirty() || current_maint.is_dirty();
    if dirty {
        eprintln!("egress-resolver: firewall chains hold unexpected rules; rewriting");
    }
    if !dirty && plan.production == current_prod_map && plan.maintenance == current_maint_map {
        eprintln!("egress-resolver: firewall chains unchanged");
    } else {
        let batch = iptables::render_restore(&cfg.firewall, &plan.production, &plan.maintenance);
        match iptables::apply_restore(exec, &batch) {
            Ok(()) => match verify_chains(cfg, exec, &plan) {
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
            },
            Err(e) => {
                apply_ok = false;
                errors.push(e);
            }
        }
    }

    // Everything below describes the policy that is actually installed. When
    // the update failed, that is the previous chain; re-read it so a partially
    // applied batch (if any) is reflected, and derive the per-name state from
    // its comments.
    let (names, effective_prod, effective_maint) = if apply_ok {
        (
            plan.names.clone(),
            plan.production.clone(),
            plan.maintenance.clone(),
        )
    } else {
        let prod = iptables::read_chain(exec, &cfg.firewall.production_chain)
            .map(|c| c.entries)
            .unwrap_or(current_prod.entries.clone());
        let maint = iptables::read_chain(exec, &cfg.firewall.maintenance_chain)
            .map(|c| c.entries)
            .unwrap_or(current_maint.entries.clone());
        (
            plan::names_from_kernel(
                cfg,
                &prod,
                "firewall update failed; previous policy retained",
            ),
            entries_to_map(&prod),
            entries_to_map(&maint),
        )
    };

    // 2. Hosts file, from the installed policy only.
    let hosts_text = hosts::render(&cfg.static_hosts, &names);
    let hosts_ok = match sysutil::write_atomic(&opts.hosts, &hosts_text, 0o644) {
        Ok(()) => true,
        Err(e) => {
            errors.push(format!("writing {}: {e}", opts.hosts.display()));
            false
        }
    };

    // 3. Connection hygiene, derived from the installed policy and the mode.
    let mode = sysutil::read_mode(&opts.state_file);
    let to_kill = conntrack::kill_set(&mode, &effective_prod, &effective_maint);
    let failed = conntrack::kill(exec, &to_kill);
    let kill_failed: Vec<_> = failed.iter().map(|(ip, _)| *ip).collect();
    for (ip, e) in &failed {
        errors.push(format!("conntrack -D {ip}: {e}"));
    }
    let killed: Vec<_> = to_kill
        .iter()
        .copied()
        .filter(|ip| !kill_failed.contains(ip))
        .collect();

    // 4. Freshness bookkeeping: when each name's installed addresses last came
    //    from a fresh authenticated answer. Names whose source is fresh in this
    //    run (only possible when the update succeeded) get "now"; the rest
    //    carry the previous run's value forward.
    let generated_uptime_secs = sysutil::uptime_secs().unwrap_or(now_uptime);
    let mut last_fresh_uptime_secs = prev.last_fresh_uptime_secs;
    last_fresh_uptime_secs.retain(|name, _| names.iter().any(|n| &n.name == name));
    for n in names
        .iter()
        .filter(|n| matches!(n.source, plan::Source::Fresh | plan::Source::Empty))
    {
        last_fresh_uptime_secs.insert(n.name.clone(), generated_uptime_secs);
    }

    let st = status::Status {
        schema: status::SCHEMA,
        boot_id,
        generated_uptime_secs,
        answers_uptime_secs: answers_uptime,
        applied_answers_uptime_secs,
        mode,
        apply_ok,
        hosts_ok,
        conntrack_ok: kill_failed.is_empty(),
        required_satisfied: apply_ok && hosts_ok && plan::required_satisfied(&names),
        required_fresh: apply_ok && plan::required_fresh(&names),
        last_fresh_uptime_secs,
        endpoints: names,
        production: effective_prod.keys().copied().collect(),
        maintenance: effective_maint.keys().copied().collect(),
        added: if apply_ok {
            plan.added.clone()
        } else {
            Vec::new()
        },
        removed: if apply_ok {
            plan.removed.clone()
        } else {
            Vec::new()
        },
        killed,
        kill_failed,
        errors,
    };
    if let Err(e) = sysutil::write_atomic(&opts.status, &st.to_json(), 0o644) {
        eprintln!(
            "egress-resolver: warning: writing {}: {e}",
            opts.status.display()
        );
    }
    if let Err(e) = sysutil::write_atomic(&opts.metrics, &st.to_metrics(), 0o644) {
        eprintln!(
            "egress-resolver: warning: writing {}: {e}",
            opts.metrics.display()
        );
    }
    Ok(st)
}

/// Read both chains back after a restore and require them to equal the plan.
fn verify_chains(cfg: &Config, exec: &mut dyn Exec, plan: &plan::Plan) -> Result<(), String> {
    let prod = iptables::read_chain(exec, &cfg.firewall.production_chain)?;
    let maint = iptables::read_chain(exec, &cfg.firewall.maintenance_chain)?;
    let mut problems = Vec::new();
    if prod.is_dirty()
        || prod.entries.len() != plan.production.len()
        || entries_to_map(&prod.entries) != plan.production
    {
        problems.push(format!(
            "{} holds {} rule(s) after restore, expected {}",
            cfg.firewall.production_chain,
            prod.rule_lines,
            plan.production.len()
        ));
    }
    if maint.is_dirty()
        || maint.entries.len() != plan.maintenance.len()
        || entries_to_map(&maint.entries) != plan.maintenance
    {
        problems.push(format!(
            "{} holds {} rule(s) after restore, expected {}",
            cfg.firewall.maintenance_chain,
            maint.rule_lines,
            plan.maintenance.len()
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "post-apply verification failed: {}",
            problems.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answers::{Answers, NameResult, Outcome};
    use crate::exec::fake::FakeExec;
    use std::fs;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_command_and_options() {
        let (cmd, o) = parse_args(&args(&[
            "apply",
            "--config",
            "/tmp/c.toml",
            "--lock-timeout",
            "5",
        ]))
        .unwrap();
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

    // ---- run_apply end-to-end with a scripted iptables/conntrack ----

    const CFG: &str = r#"
[resolver]
servers = ["1.1.1.1"]
server_name = "cloudflare-dns.com"
[firewall]
production_chain = "P"
maintenance_chain = "M"
max_addresses = 3
[[endpoint]]
name = "rpc.buildernet.org"
required = true
[[endpoint]]
name = "direct-ap.buildernet.org"
[[static_host]]
ip = "3.149.14.12"
names = ["tx.tee-searcher.flashbots.net"]
"#;

    struct Harness {
        dir: PathBuf,
        cfg: Config,
        opts: Opts,
    }

    impl Harness {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "egress-resolver-apply-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let opts = Opts {
                config: dir.join("cfg.toml"),
                answers: dir.join("answers.json"),
                hosts: dir.join("hosts"),
                status: dir.join("status.json"),
                metrics: dir.join("egress.prom"),
                state_file: dir.join("state"),
                lock: dir.join("lock"),
                lock_timeout: Duration::from_secs(2),
            };
            fs::write(&opts.state_file, "maintenance\n").unwrap();
            Self {
                dir,
                cfg: Config::parse(CFG).unwrap(),
                opts,
            }
        }

        fn mode(&self, m: &str) {
            fs::write(&self.opts.state_file, format!("{m}\n")).unwrap();
        }

        fn answers(&self, results: Vec<NameResult>, generated_uptime_secs: f64) {
            let a = Answers {
                schema: answers::SCHEMA,
                generated_uptime_secs,
                results,
            };
            fs::write(&self.opts.answers, serde_json::to_string(&a).unwrap()).unwrap();
        }

        fn hosts(&self) -> String {
            fs::read_to_string(&self.opts.hosts).unwrap_or_default()
        }

        fn status_json(&self) -> serde_json::Value {
            serde_json::from_str(&fs::read_to_string(&self.opts.status).unwrap()).unwrap()
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn ok(name: &str, addrs: &[&str]) -> NameResult {
        NameResult {
            name: name.into(),
            outcome: Outcome::Ok,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            min_ttl: Some(300),
            server: Some("1.1.1.1:853".into()),
            error: None,
        }
    }

    /// `iptables -S <chain>` output for the given (ip, names) rules.
    fn chain(chain: &str, rules: &[(&str, &str)]) -> String {
        let mut s = format!("-N {chain}\n");
        for (ip, names) in rules {
            if chain == "P" {
                s.push_str(&format!(
                    "-A P -d {ip}/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -m comment --comment \"{names}\" -j ACCEPT\n"
                ));
            } else {
                s.push_str(&format!(
                    "-A M -d {ip}/32 -m comment --comment \"{names}\" -j DROP\n"
                ));
            }
        }
        s
    }

    const A: &str = "200.225.47.181";
    const B: &str = "200.225.47.183";
    const AP: &str = "35.213.62.127";

    #[test]
    fn happy_path_updates_chains_hosts_and_sweeps_in_maintenance() {
        let h = Harness::new("happy");
        h.answers(
            vec![
                ok("rpc.buildernet.org", &[A]),
                ok("direct-ap.buildernet.org", &[AP]),
            ],
            100.0,
        );
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[])) // read P
            .respond(0, &chain("M", &[])) // read M
            .respond(0, "") // restore
            .respond(
                0,
                &chain(
                    "P",
                    &[(A, "rpc.buildernet.org"), (AP, "direct-ap.buildernet.org")],
                ),
            ) // verify P
            .respond(
                0,
                &chain(
                    "M",
                    &[(A, "rpc.buildernet.org"), (AP, "direct-ap.buildernet.org")],
                ),
            ) // verify M
            .respond(1, "0 flow entries have been deleted.") // conntrack A
            .respond(0, ""); // conntrack AP
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.all_ok(), "{:?}", st.errors);
        assert!(st.required_satisfied && st.required_fresh);
        assert_eq!(
            st.killed.len(),
            2,
            "maintenance sweep kills every known address"
        );
        assert!(
            ex.calls[2].args.contains(&"-n".to_string()),
            "restore uses -n"
        );
        // sweep order is numeric: 35.213.62.127 before 200.225.47.181
        assert_eq!(ex.calls[5].args, vec!["-D", "-d", AP]);
        assert_eq!(ex.calls[6].args, vec!["-D", "-d", A]);
        let hosts = h.hosts();
        assert!(hosts.contains(&format!("{A} rpc.buildernet.org")));
        assert!(hosts.contains("3.149.14.12 tx.tee-searcher.flashbots.net"));
        assert_eq!(h.status_json()["schema"], status::SCHEMA);
    }

    #[test]
    fn production_mode_only_sweeps_retired_addresses() {
        let h = Harness::new("prod");
        h.mode("production");
        // B retired: present in M from before, no longer resolved
        h.answers(vec![ok("rpc.buildernet.org", &[A])], 100.0);
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(
                0,
                &chain("M", &[(A, "rpc.buildernet.org"), (B, "rpc.buildernet.org")]),
            )
            .respond(0, ""); // conntrack B
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.all_ok());
        assert_eq!(st.killed, vec![B.parse::<std::net::Ipv4Addr>().unwrap()]);
        assert_eq!(ex.calls.len(), 3, "unchanged chains: no restore, one kill");
    }

    #[test]
    fn over_limit_answers_keep_previous_chain_and_previous_hosts() {
        let h = Harness::new("overlimit");
        h.answers(
            vec![
                ok("rpc.buildernet.org", &["1.1.1.1", "1.1.1.2", "1.1.1.3"]),
                ok("direct-ap.buildernet.org", &["1.1.1.4"]),
            ],
            100.0,
        );
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, ""); // conntrack A (maintenance)
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.apply_ok && st.hosts_ok);
        assert!(st.errors.iter().any(|e| e.contains("max_addresses")));
        assert!(st.required_satisfied, "rpc keeps its installed address");
        assert!(!st.required_fresh);
        let hosts = h.hosts();
        assert!(hosts.contains(&format!("{A} rpc.buildernet.org")));
        assert!(
            !hosts.contains("1.1.1.1"),
            "rejected candidate must not be published:\n{hosts}"
        );
        assert_eq!(ex.calls.len(), 3, "no restore attempted");
    }

    #[test]
    fn failed_restore_publishes_previous_mappings_not_candidate() {
        let h = Harness::new("restorefail");
        h.answers(vec![ok("rpc.buildernet.org", &[B])], 100.0);
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(1, "") // restore fails
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")])) // re-read P
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")])) // re-read M
            .respond(0, ""); // conntrack A (maintenance)
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(!st.apply_ok && !st.all_ok());
        assert!(st.hosts_ok);
        let hosts = h.hosts();
        assert!(
            hosts.contains(&format!("{A} rpc.buildernet.org")),
            "previous mapping kept:\n{hosts}"
        );
        assert!(
            !hosts.contains(B),
            "candidate must not be published:\n{hosts}"
        );
        assert_eq!(
            st.production,
            vec![A.parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert!(
            !st.required_satisfied,
            "production must be refused after a failed update"
        );
        assert!(st.added.is_empty() && st.removed.is_empty());
    }

    #[test]
    fn post_apply_verification_catches_chain_mismatch() {
        let h = Harness::new("verify");
        h.answers(vec![ok("rpc.buildernet.org", &[A])], 100.0);
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[]))
            .respond(0, &chain("M", &[]))
            .respond(0, "") // restore "succeeds"
            .respond(
                0,
                &chain("P", &[(A, "rpc.buildernet.org"), (A, "rpc.buildernet.org")]),
            ) // duplicate rule
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(
                0,
                &chain("P", &[(A, "rpc.buildernet.org"), (A, "rpc.buildernet.org")]),
            ) // re-read
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(!st.apply_ok);
        assert!(
            st.errors
                .iter()
                .any(|e| e.contains("post-apply verification failed")),
            "{:?}",
            st.errors
        );
    }

    #[test]
    fn hosts_write_failure_is_reported_and_blocks_readiness() {
        let mut h = Harness::new("hostsfail");
        h.opts.hosts = h.dir.join("missing-dir").join("hosts");
        h.answers(vec![ok("rpc.buildernet.org", &[A])], 100.0);
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.apply_ok && !st.hosts_ok && !st.all_ok());
        assert!(!st.required_satisfied);
        assert!(st.errors.iter().any(|e| e.contains("hosts")));
    }

    #[test]
    fn conntrack_failure_is_reported_per_address() {
        let h = Harness::new("ctfail");
        h.answers(
            vec![
                ok("rpc.buildernet.org", &[A]),
                ok("direct-ap.buildernet.org", &[AP]),
            ],
            100.0,
        );
        let mut ex = FakeExec::default()
            .respond(
                0,
                &chain(
                    "P",
                    &[(A, "rpc.buildernet.org"), (AP, "direct-ap.buildernet.org")],
                ),
            )
            .respond(
                0,
                &chain(
                    "M",
                    &[(A, "rpc.buildernet.org"), (AP, "direct-ap.buildernet.org")],
                ),
            )
            .respond(2, "") // conntrack AP (first in numeric order) fails
            .respond(0, ""); // conntrack A ok
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.apply_ok && st.hosts_ok && !st.conntrack_ok && !st.all_ok());
        assert_eq!(
            st.kill_failed,
            vec![AP.parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(st.killed, vec![A.parse::<std::net::Ipv4Addr>().unwrap()]);
        assert!(st.errors.iter().any(|e| e.contains(AP)));
        assert!(
            st.required_satisfied,
            "a sweep failure does not affect admission"
        );
    }

    #[test]
    fn missing_or_stale_answers_keep_last_known_good() {
        let h = Harness::new("stale");
        // no answers file at all
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.apply_ok && st.required_satisfied && !st.required_fresh);
        assert!(st.errors.iter().any(|e| e.contains("cannot read answers")));
        assert_eq!(st.endpoints[0].source, plan::Source::LastKnownGood);
        // stale answers (older than ANSWERS_MAX_AGE_SECS) are treated the same
        h.answers(vec![ok("rpc.buildernet.org", &[B])], 100.0);
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 100.0 + ANSWERS_MAX_AGE_SECS + 1.0).unwrap();
        assert!(
            st.errors.iter().any(|e| e.contains("old")),
            "{:?}",
            st.errors
        );
        assert_eq!(
            st.production,
            vec![A.parse::<std::net::Ipv4Addr>().unwrap()],
            "B must not be applied"
        );
        assert_eq!(ex.calls.len(), 3, "no restore");
    }

    #[test]
    fn answers_already_applied_by_the_previous_run_are_not_fresh() {
        let h = Harness::new("consumed");
        h.answers(vec![ok("rpc.buildernet.org", &[A])], 100.0);
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[]))
            .respond(0, &chain("M", &[]))
            .respond(0, "") // restore
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, ""); // conntrack A
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.all_ok() && st.required_fresh);
        assert!(st.last_fresh_uptime_secs.contains_key("rpc.buildernet.org"));
        let first_fresh = st.last_fresh_uptime_secs["rpc.buildernet.org"];
        // same answers file again (resolve step produced nothing new)
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 120.0).unwrap();
        assert!(st.all_ok() && st.required_satisfied);
        assert!(!st.required_fresh, "nothing was freshly resolved");
        assert!(
            st.errors.iter().any(|e| e.contains("already applied")),
            "{:?}",
            st.errors
        );
        assert_eq!(st.endpoints[0].source, plan::Source::LastKnownGood);
        assert_eq!(
            st.last_fresh_uptime_secs["rpc.buildernet.org"], first_fresh,
            "last fresh time is carried forward, not refreshed"
        );
        assert_eq!(ex.calls.len(), 3, "no restore");
        assert!(st
            .to_metrics()
            .contains("egress_resolver_endpoint_fresh_age_seconds{name=\"rpc.buildernet.org\"}"));
        assert_eq!(st.applied_answers_uptime_secs, Some(100.0));
        // third run, same file, still under the age limit: the marker must
        // have survived the rejected run, so the file is rejected again and
        // the freshness bookkeeping does not reset
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 180.0).unwrap();
        assert!(
            !st.required_fresh,
            "an unchanged file must not become fresh again"
        );
        assert!(
            st.errors.iter().any(|e| e.contains("already applied")),
            "{:?}",
            st.errors
        );
        assert_eq!(st.last_fresh_uptime_secs["rpc.buildernet.org"], first_fresh);
        assert_eq!(st.answers_uptime_secs, None, "no usable answers this run");
        assert_eq!(
            st.applied_answers_uptime_secs,
            Some(100.0),
            "consumed marker carried across the rejected run"
        );
        assert_eq!(h.status_json()["applied_answers_uptime_secs"], 100.0);
        assert_eq!(ex.calls.len(), 3, "no restore");
    }

    #[test]
    fn dirty_chain_is_rewritten_even_when_addresses_match() {
        let h = Harness::new("dirty");
        h.answers(vec![ok("rpc.buildernet.org", &[A])], 100.0);
        // P holds the right address plus a rule without a destination
        let mut dirty_p = chain("P", &[(A, "rpc.buildernet.org")]);
        dirty_p.push_str("-A P -p tcp -m tcp --dport 443 -j ACCEPT\n");
        let mut ex = FakeExec::default()
            .respond(0, &dirty_p)
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "") // restore
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, ""); // conntrack A
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(st.all_ok(), "{:?}", st.errors);
        assert_eq!(
            ex.calls[2].program,
            iptables::IPTABLES_RESTORE,
            "chain was rewritten"
        );
        assert!(st.added.is_empty() && st.removed.is_empty());
        // duplicate rules count as dirty too
        let mut ex = FakeExec::default()
            .respond(
                0,
                &chain("P", &[(A, "rpc.buildernet.org"), (A, "rpc.buildernet.org")]),
            )
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "")
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 120.0).unwrap();
        assert!(st.apply_ok, "{:?}", st.errors);
        assert_eq!(ex.calls[2].program, iptables::IPTABLES_RESTORE);
    }

    #[test]
    fn symlinked_answers_file_is_rejected() {
        let h = Harness::new("symlink");
        let target = h.dir.join("real.json");
        let a = Answers {
            schema: answers::SCHEMA,
            generated_uptime_secs: 100.0,
            results: vec![ok("rpc.buildernet.org", &[B])],
        };
        fs::write(&target, serde_json::to_string(&a).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &h.opts.answers).unwrap();
        let mut ex = FakeExec::default()
            .respond(0, &chain("P", &[(A, "rpc.buildernet.org")]))
            .respond(0, &chain("M", &[(A, "rpc.buildernet.org")]))
            .respond(0, "");
        let st = run_apply(&h.cfg, &h.opts, &mut ex, 110.0).unwrap();
        assert!(
            st.errors.iter().any(|e| e.contains("cannot read answers")),
            "{:?}",
            st.errors
        );
        assert_eq!(
            st.production,
            vec![A.parse::<std::net::Ipv4Addr>().unwrap()],
            "B from the symlink target must not be applied"
        );
    }
}
