//! DNS-over-TLS resolution of the configured names.
//!
//! Each configured resolver is tried in order. A name is settled as soon as one
//! resolver returns an authenticated positive or negative answer; SERVFAIL,
//! timeouts, TLS failures and unauthenticated answers are transient and fall
//! through to the next resolver.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use hickory_net::proto::op::{DnsRequestOptions, Query, ResponseCode};
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

/// Outcome of one query against one resolver.
#[derive(Debug)]
enum Classified {
    Ok { addrs: Vec<Ipv4Addr>, min_ttl: u32 },
    Empty(String),
    /// `retry`: whether asking the same resolver again can help (timeouts,
    /// SERVFAIL) or not (deterministic answers such as a missing AD bit).
    Transient { reason: String, retry: bool },
}

fn transient(reason: impl Into<String>) -> Classified {
    Classified::Transient { reason: reason.into(), retry: true }
}

fn permanent(reason: impl Into<String>) -> Classified {
    Classified::Transient { reason: reason.into(), retry: false }
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
    let cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Resolve every endpoint. Never fails: unresolvable names are reported as
/// `Transient` so the caller can keep their last-known-good addresses.
pub async fn resolve_all(cfg: &Config, uptime_secs: f64) -> Answers {
    let names = cfg.endpoint_names();
    let mut results: Vec<Option<NameResult>> = vec![None; names.len()];
    let mut last_error: Vec<String> = vec![String::from("not attempted"); names.len()];
    let query_timeout = Duration::from_secs(cfg.resolver.timeout_secs);

    let tls = match tls_config() {
        Ok(t) => Some(t),
        Err(e) => {
            log(&format!("tls configuration failed: {e}"));
            for le in &mut last_error {
                *le = format!("tls configuration failed: {e}");
            }
            None
        }
    };

    if let Some(tls) = tls {
        for server in &cfg.resolver.servers {
            if results.iter().all(|r| r.is_some()) {
                break;
            }
            let addr = SocketAddr::new((*server).into(), cfg.resolver.port);
            let exchange = match connect(addr, &cfg.resolver.server_name, tls.clone(), query_timeout).await {
                Ok(x) => x,
                Err(e) => {
                    log(&format!("resolver {addr}: connect failed: {e}"));
                    for (i, r) in results.iter().enumerate() {
                        if r.is_none() {
                            last_error[i] = format!("{addr}: connect failed: {e}");
                        }
                    }
                    continue;
                }
            };
            for (i, name) in names.iter().enumerate() {
                if results[i].is_some() {
                    continue;
                }
                let mut transient = None;
                for attempt in 1..=cfg.resolver.attempts {
                    match query(&exchange, name, query_timeout, cfg.resolver.require_authenticated).await {
                        Classified::Ok { addrs, min_ttl } => {
                            log(&format!("{name}: {} address(es) via {addr} (ttl {min_ttl})", addrs.len()));
                            results[i] = Some(NameResult {
                                name: name.clone(),
                                outcome: Outcome::Ok,
                                addrs,
                                min_ttl: Some(min_ttl),
                                server: Some(addr.to_string()),
                                error: None,
                            });
                            break;
                        }
                        Classified::Empty(reason) => {
                            log(&format!("{name}: authenticated negative answer via {addr}: {reason}"));
                            results[i] = Some(NameResult {
                                name: name.clone(),
                                outcome: Outcome::Empty,
                                addrs: Vec::new(),
                                min_ttl: None,
                                server: Some(addr.to_string()),
                                error: Some(reason),
                            });
                            break;
                        }
                        Classified::Transient { reason, retry } => {
                            log(&format!("{name}: attempt {attempt}/{} via {addr} failed: {reason}", cfg.resolver.attempts));
                            transient = Some(format!("{addr}: {reason}"));
                            if !retry {
                                break;
                            }
                            if attempt < cfg.resolver.attempts {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
                if let Some(t) = transient {
                    if results[i].is_none() {
                        last_error[i] = t;
                    }
                }
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

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    tls: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<DnsExchange<TokioRuntimeProvider>, String> {
    let sni = ServerName::try_from(server_name.to_string()).map_err(|e| format!("bad server_name: {e}"))?;
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
    let mut q = Query::query(qname, RecordType::A);
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

    let ad = response.metadata.authentic_data;
    if response.metadata.truncation {
        return transient("truncated response");
    }
    match response.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            return if require_authenticated && !ad {
                permanent("NXDOMAIN without AD bit")
            } else {
                Classified::Empty("NXDOMAIN".into())
            };
        }
        other => return transient(format!("rcode {other}")),
    }
    if require_authenticated && !ad {
        return permanent("answer not authenticated (AD bit missing)");
    }

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for record in &response.answers {
        if let RData::A(a) = &record.data {
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
        return Classified::Empty("NODATA (no A records)".into());
    }
    Classified::Ok { addrs, min_ttl }
}

fn log(msg: &str) {
    eprintln!("egress-resolver: {msg}");
}
