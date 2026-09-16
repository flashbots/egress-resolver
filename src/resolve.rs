//! DNS-over-TLS resolution of the configured names.
//!
//! Each configured resolver is tried in order; all names still unsettled are
//! queried concurrently over one multiplexed connection. A name is settled as
//! soon as one resolver returns an authenticated positive or negative answer.
//! SERVFAIL, timeouts and TLS failures are transient and fall through to the
//! next resolver; deterministic rejections (missing AD bit, non-global address)
//! are not retried on the same resolver.
//!
//! The whole run is bounded by `resolver.deadline_secs`: whatever is unsettled
//! when the budget expires is reported as transient, so `apply` always gets an
//! answers file in time.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use futures_util::StreamExt;
use hickory_net::proto::op::{DnsRequestOptions, Message, Query, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tls::tls_client_connect;
use hickory_net::xfer::{DnsExchange, DnsMultiplexer};
use hickory_net::DnsHandle;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};

use crate::answers::{Answers, NameResult, Outcome};
use crate::config::Config;
use crate::validate::is_global_unicast;

/// Longest CNAME chain followed from the queried name.
pub const MAX_CNAME_HOPS: usize = 8;

/// Outcome of one query against one resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// Authenticated answer with at least one valid A record for the queried
    /// name (or the end of its CNAME chain).
    Ok { addrs: Vec<Ipv4Addr>, min_ttl: u32 },
    /// Authenticated proof that the name has no A records.
    Empty(String),
    /// No usable answer. `retry`: whether asking the same resolver again can
    /// help (timeouts, SERVFAIL) or not (deterministic answers such as a
    /// missing AD bit).
    Transient { reason: String, retry: bool },
}

fn transient(reason: impl Into<String>) -> Classified {
    Classified::Transient {
        reason: reason.into(),
        retry: true,
    }
}

fn permanent(reason: impl Into<String>) -> Classified {
    Classified::Transient {
        reason: reason.into(),
        retry: false,
    }
}

/// Classify a response to an `A` query for `qname`.
///
/// Only records owned by the queried name, or by the target of a CNAME chain
/// that starts at the queried name, are considered. Unrelated records in the
/// answer section never contribute addresses.
pub fn classify(msg: &Message, qname: &Name, require_authenticated: bool) -> Classified {
    if msg.metadata.truncation {
        return transient("truncated response");
    }
    let ad = msg.metadata.authentic_data;
    match msg.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            return if require_authenticated && !ad {
                permanent("NXDOMAIN without AD bit")
            } else {
                Classified::Empty("NXDOMAIN".into())
            };
        }
        other => return transient(format!("rcode {other:?}")),
    }
    if require_authenticated && !ad {
        return permanent("answer not authenticated (AD bit missing)");
    }

    // Follow the CNAME chain from the queried name within the answer section.
    let mut owner = qname.clone();
    owner.set_fqdn(true);
    let mut seen = BTreeSet::new();
    seen.insert(owner.to_lowercase());
    for _ in 0..MAX_CNAME_HOPS {
        let next = msg.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if r.name == owner => Some(target.0.clone()),
            _ => None,
        });
        match next {
            Some(mut target) => {
                target.set_fqdn(true);
                if !seen.insert(target.to_lowercase()) {
                    return permanent("CNAME loop in answer");
                }
                owner = target;
            }
            None => break,
        }
    }

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    let mut unrelated = 0usize;
    for record in &msg.answers {
        if let RData::A(a) = &record.data {
            if record.name != owner {
                unrelated += 1;
                continue;
            }
            let ip = a.0;
            if !is_global_unicast(ip) {
                return permanent(format!("answer contains non-global address {ip}"));
            }
            if !addrs.contains(&ip) {
                addrs.push(ip);
            }
            min_ttl = min_ttl.min(record.ttl);
        }
    }
    if addrs.is_empty() {
        if unrelated > 0 {
            return permanent(format!(
                "answer has {unrelated} A record(s) but none for the queried name"
            ));
        }
        return Classified::Empty("NODATA (no A records)".into());
    }
    Classified::Ok { addrs, min_ttl }
}

pub fn tls_config() -> Result<Arc<ClientConfig>, String> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        return Err(format!(
            "no CA certificates loaded from the system store ({} error(s): {:?})",
            loaded.errors.len(),
            loaded.errors
        ));
    }
    let cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls protocol versions: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Resolve every endpoint within `resolver.deadline_secs`. Never fails:
/// unresolved names are reported as `Transient` so the caller keeps their
/// last-known-good addresses.
pub async fn resolve_all(cfg: &Config, uptime_secs: f64) -> Answers {
    let names = cfg.endpoint_names();
    let mut results: Vec<Option<NameResult>> = vec![None; names.len()];
    let mut last_error: Vec<String> = vec![String::from("not attempted"); names.len()];
    let deadline = Duration::from_secs(cfg.resolver.deadline_secs);

    let run = resolve_servers(cfg, &names, &mut results, &mut last_error);
    if tokio::time::timeout(deadline, run).await.is_err() {
        log(&format!(
            "deadline of {}s reached; unsettled names keep their previous addresses",
            cfg.resolver.deadline_secs
        ));
        for (i, r) in results.iter().enumerate() {
            if r.is_none() {
                last_error[i] = format!(
                    "deadline of {}s exceeded ({})",
                    cfg.resolver.deadline_secs, last_error[i]
                );
            }
        }
    }

    let results = results
        .into_iter()
        .zip(names)
        .zip(last_error)
        .map(|((r, name), err)| {
            r.unwrap_or(NameResult {
                name,
                outcome: Outcome::Transient,
                addrs: Vec::new(),
                min_ttl: None,
                server: None,
                error: Some(err),
            })
        })
        .collect();

    Answers {
        schema: crate::answers::SCHEMA,
        generated_uptime_secs: uptime_secs,
        results,
    }
}

async fn resolve_servers(
    cfg: &Config,
    names: &[String],
    results: &mut [Option<NameResult>],
    last_error: &mut [String],
) {
    let query_timeout = Duration::from_secs(cfg.resolver.timeout_secs);
    let tls = match tls_config() {
        Ok(t) => t,
        Err(e) => {
            log(&format!("tls configuration failed: {e}"));
            for le in last_error.iter_mut() {
                *le = format!("tls configuration failed: {e}");
            }
            return;
        }
    };

    for server in &cfg.resolver.servers {
        let pending: Vec<usize> = (0..names.len()).filter(|i| results[*i].is_none()).collect();
        if pending.is_empty() {
            break;
        }
        let addr = SocketAddr::new((*server).into(), cfg.resolver.port);
        let exchange =
            match connect(addr, &cfg.resolver.server_name, tls.clone(), query_timeout).await {
                Ok(x) => x,
                Err(e) => {
                    log(&format!("resolver {addr}: connect failed: {e}"));
                    for &i in &pending {
                        last_error[i] = format!("{addr}: connect failed: {e}");
                    }
                    continue;
                }
            };
        let outcomes = join_all(pending.iter().map(|&i| {
            resolve_name(
                &exchange,
                &names[i],
                addr,
                cfg.resolver.attempts,
                query_timeout,
                cfg.resolver.require_authenticated,
            )
        }))
        .await;
        for (i, outcome) in pending.into_iter().zip(outcomes) {
            match outcome {
                Ok(r) => results[i] = Some(r),
                Err(e) => last_error[i] = e,
            }
        }
    }
}

/// Query one name on one resolver, retrying retryable transient failures.
/// `Err` carries the last transient reason.
async fn resolve_name(
    exchange: &DnsExchange<TokioRuntimeProvider>,
    name: &str,
    addr: SocketAddr,
    attempts: u32,
    timeout: Duration,
    require_authenticated: bool,
) -> Result<NameResult, String> {
    let mut last = String::from("no attempt");
    for attempt in 1..=attempts {
        match query(exchange, name, timeout, require_authenticated).await {
            Classified::Ok { addrs, min_ttl } => {
                log(&format!(
                    "{name}: {} address(es) via {addr} (ttl {min_ttl})",
                    addrs.len()
                ));
                return Ok(NameResult {
                    name: name.to_string(),
                    outcome: Outcome::Ok,
                    addrs,
                    min_ttl: Some(min_ttl),
                    server: Some(addr.to_string()),
                    error: None,
                });
            }
            Classified::Empty(reason) => {
                log(&format!(
                    "{name}: authenticated negative answer via {addr}: {reason}"
                ));
                return Ok(NameResult {
                    name: name.to_string(),
                    outcome: Outcome::Empty,
                    addrs: Vec::new(),
                    min_ttl: None,
                    server: Some(addr.to_string()),
                    error: Some(reason),
                });
            }
            Classified::Transient { reason, retry } => {
                log(&format!(
                    "{name}: attempt {attempt}/{attempts} via {addr} failed: {reason}"
                ));
                last = format!("{addr}: {reason}");
                if !retry {
                    break;
                }
                if attempt < attempts {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    Err(last)
}

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    tls: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<DnsExchange<TokioRuntimeProvider>, String> {
    let sni = ServerName::try_from(server_name.to_string())
        .map_err(|e| format!("bad server_name: {e}"))?;
    let provider = TokioRuntimeProvider::new();
    let (stream_future, handle) = tls_client_connect(addr, sni, tls, provider);
    let stream = tokio::time::timeout(timeout, stream_future)
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let multiplexer = DnsMultiplexer::new(stream, handle).with_timeout(timeout);
    let (exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(multiplexer);
    tokio::spawn(background);
    Ok(exchange)
}

async fn query(
    exchange: &DnsExchange<TokioRuntimeProvider>,
    name: &str,
    timeout: Duration,
    require_authenticated: bool,
) -> Classified {
    let mut qname = match Name::from_ascii(name) {
        Ok(n) => n,
        Err(e) => return permanent(format!("invalid name: {e}")),
    };
    qname.set_fqdn(true);
    let mut q = Query::query(qname.clone(), RecordType::A);
    q.query_class = DNSClass::IN;

    let mut opts = DnsRequestOptions::default();
    opts.use_edns = true;
    opts.edns_set_dnssec_ok = true;
    opts.recursion_desired = true;

    let mut stream = exchange.lookup(q, opts);
    let response = match tokio::time::timeout(timeout, stream.next()).await {
        Err(_) => return transient("timeout"),
        Ok(None) => return transient("connection closed"),
        Ok(Some(Err(e))) => return transient(format!("dns error: {e}")),
        Ok(Some(Ok(r))) => r,
    };
    classify(&response, &qname, require_authenticated)
}

fn log(msg: &str) {
    eprintln!("egress-resolver: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::rr::rdata::{A, CNAME};
    use hickory_net::proto::rr::Record;

    fn name(s: &str) -> Name {
        let mut n = Name::from_ascii(s).unwrap();
        n.set_fqdn(true);
        n
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn a(owner: &str, ttl: u32, addr: &str) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(ip(addr))))
    }

    fn cname(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
    }

    fn response(ad: bool, rcode: ResponseCode, answers: Vec<Record>) -> Message {
        let mut m = Message::query();
        m.metadata.authentic_data = ad;
        m.metadata.response_code = rcode;
        m.answers = answers;
        m
    }

    const Q: &str = "rpc.buildernet.org";

    #[test]
    fn direct_a_records_are_accepted_deduplicated_with_min_ttl() {
        let m = response(
            true,
            ResponseCode::NoError,
            vec![
                a(Q, 300, "200.225.47.181"),
                a(Q, 120, "200.225.47.183"),
                a(Q, 300, "200.225.47.181"),
            ],
        );
        assert_eq!(
            classify(&m, &name(Q), true),
            Classified::Ok {
                addrs: vec![ip("200.225.47.181"), ip("200.225.47.183")],
                min_ttl: 120
            }
        );
    }

    #[test]
    fn owner_name_comparison_is_case_insensitive() {
        let m = response(
            true,
            ResponseCode::NoError,
            vec![a("RPC.BuilderNet.org", 300, "200.225.47.181")],
        );
        assert!(matches!(
            classify(&m, &name(Q), true),
            Classified::Ok { .. }
        ));
    }

    #[test]
    fn cname_chain_is_followed_to_its_target() {
        let m = response(
            true,
            ResponseCode::NoError,
            vec![
                cname(Q, "lb.buildernet.org"),
                cname("lb.buildernet.org", "node.example.net"),
                a("node.example.net", 60, "35.213.62.127"),
            ],
        );
        assert_eq!(
            classify(&m, &name(Q), true),
            Classified::Ok {
                addrs: vec![ip("35.213.62.127")],
                min_ttl: 60
            }
        );
    }

    #[test]
    fn unrelated_a_records_do_not_contribute_addresses() {
        // A records for another owner must never end up in the allowlist.
        let m = response(
            true,
            ResponseCode::NoError,
            vec![
                a("evil.example.com", 300, "203.0.113.9"),
                a("direct-us.buildernet.org", 300, "200.225.47.181"),
            ],
        );
        match classify(&m, &name(Q), true) {
            Classified::Transient { reason, retry } => {
                assert!(!retry);
                assert!(reason.contains("none for the queried name"), "{reason}");
            }
            other => panic!("unexpected {other:?}"),
        }
        // ...and are ignored when the queried name has its own records.
        let m = response(
            true,
            ResponseCode::NoError,
            vec![
                a("evil.example.com", 300, "8.8.8.8"),
                a(Q, 300, "200.225.47.181"),
            ],
        );
        assert_eq!(
            classify(&m, &name(Q), true),
            Classified::Ok {
                addrs: vec![ip("200.225.47.181")],
                min_ttl: 300
            }
        );
    }

    #[test]
    fn cname_only_response_is_authenticated_nodata() {
        let m = response(
            true,
            ResponseCode::NoError,
            vec![cname(Q, "gone.buildernet.org")],
        );
        assert!(matches!(classify(&m, &name(Q), true), Classified::Empty(_)));
    }

    #[test]
    fn cname_loop_is_rejected() {
        let m = response(
            true,
            ResponseCode::NoError,
            vec![cname(Q, "b.example"), cname("b.example", Q)],
        );
        assert_eq!(
            classify(&m, &name(Q), true),
            permanent("CNAME loop in answer")
        );
    }

    #[test]
    fn authenticated_negatives_are_empty_unauthenticated_are_not() {
        let m = response(true, ResponseCode::NXDomain, vec![]);
        assert_eq!(
            classify(&m, &name(Q), true),
            Classified::Empty("NXDOMAIN".into())
        );
        let m = response(true, ResponseCode::NoError, vec![]);
        assert!(matches!(classify(&m, &name(Q), true), Classified::Empty(_)));
        let m = response(false, ResponseCode::NXDomain, vec![]);
        assert_eq!(
            classify(&m, &name(Q), true),
            permanent("NXDOMAIN without AD bit")
        );
        // without the requirement the negative is accepted as-is
        assert_eq!(
            classify(&m, &name(Q), false),
            Classified::Empty("NXDOMAIN".into())
        );
    }

    #[test]
    fn missing_ad_bit_is_a_non_retryable_transient() {
        let m = response(
            false,
            ResponseCode::NoError,
            vec![a(Q, 300, "200.225.47.181")],
        );
        assert_eq!(
            classify(&m, &name(Q), true),
            permanent("answer not authenticated (AD bit missing)")
        );
        assert!(matches!(
            classify(&m, &name(Q), false),
            Classified::Ok { .. }
        ));
    }

    #[test]
    fn servfail_and_truncation_are_retryable() {
        let m = response(true, ResponseCode::ServFail, vec![]);
        assert_eq!(classify(&m, &name(Q), true), transient("rcode ServFail"));
        let mut m = response(
            true,
            ResponseCode::NoError,
            vec![a(Q, 300, "200.225.47.181")],
        );
        m.metadata.truncation = true;
        assert_eq!(
            classify(&m, &name(Q), true),
            transient("truncated response")
        );
    }

    #[test]
    fn any_non_global_address_fails_the_whole_answer() {
        let m = response(
            true,
            ResponseCode::NoError,
            vec![a(Q, 300, "200.225.47.181"), a(Q, 300, "169.254.169.254")],
        );
        match classify(&m, &name(Q), true) {
            Classified::Transient { reason, retry } => {
                assert!(!retry);
                assert!(reason.contains("169.254.169.254"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
