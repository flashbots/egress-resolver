# egress-resolver

Keeps a Flashbox host's production egress allowlist and the searcher
container's `/etc/hosts` in sync with an **attested list of hostnames**, so that
BuilderNet can move nodes without a new image release while the firewall stays
a static, auditable iptables ruleset.

```
/etc/bob/egress-resolver.toml ──names──▶ resolve (uid egress-resolver, DoT/853) ──▶ answers.json
                                                                                        │
PRODUCTION_OUT  ─j─▶ DYN_BNET_PRODUCTION_OUT   ◀── apply (CAP_NET_ADMIN) ◀──────────────┘
MAINTENANCE_OUT ─j─▶ DYN_BNET_MAINTENANCE_OUT  ◀──   │
                                                     ├─▶ /run/flashbox-endpoints/hosts  (ro bind-mount into the container)
                                                     ├─▶ conntrack sweep
                                                     └─▶ status.json + Prometheus textfile
```

## How it works

Two subcommands, run as two `ExecStart=` lines of one `Type=oneshot` systemd
unit fired by a timer every minute:

1. **`resolve`** (unprivileged) queries each configured name for `A` records
   over DNS-over-TLS against the configured resolvers in order. An answer is
   accepted only if the resolver set the AD bit (DNSSEC-validated), every
   address is a global unicast IPv4 address, and the response is not
   truncated. Authenticated NXDOMAIN/NODATA is an *empty* result; SERVFAIL,
   timeouts, TLS failures and unauthenticated answers are *transient*. The
   result is written to `answers.json`.
2. **`apply`** (needs `CAP_NET_ADMIN`) takes the toggle lock and:
   * reads the two dynamic chains back from the kernel (`iptables -S`); the
     `--comment` on each rule records which name produced the address, so the
     kernel is the only state and the tool is stateless;
   * computes the new production set (fresh answers; last-known-good addresses
     for transient names; nothing for empty names) and the maintenance set
     (everything ever resolved since boot, never shrinking);
   * replaces both chains atomically with `iptables-restore -n`;
   * renders the hosts file from the same addresses;
   * deletes conntrack entries for TCP flows that must not exist in the current
     mode (production: retired addresses; otherwise: every known address);
   * writes `status.json` (consumed by `toggle` before entering production) and a
     Prometheus textfile.

Both chains are created empty by the image's `firewall-config` and are jumped
to from static rules, so `iptables-save` remains a complete description of the
policy: only the contents of the two `DYN_*` chains vary at runtime.

## Configuration

See [`examples/egress-resolver.toml`](examples/egress-resolver.toml).

```toml
[resolver]
servers = ["1.1.1.1", "1.0.0.1"]     # tried in order
server_name = "cloudflare-dns.com"   # certificate must be valid for this name
# port = 853, timeout_secs = 5, attempts = 3, require_authenticated = true

[firewall]
production_chain = "DYN_BNET_PRODUCTION_OUT"
maintenance_chain = "DYN_BNET_MAINTENANCE_OUT"
# port = 443, max_addresses = 64

[[endpoint]]
name = "rpc.buildernet.org"
required = true                       # toggle refuses production while unresolved

[[static_host]]                       # copied verbatim into the hosts file
ip = "3.149.14.12"
names = ["tx.tee-searcher.flashbots.net"]
```

## Files

| Path | Writer | Purpose |
|---|---|---|
| `/run/egress-resolver/resolve/answers.json` | `resolve` | hand-off to `apply` |
| `/run/egress-resolver/status.json` | `apply` | mode, per-name state, `required_satisfied`, errors; uptime-based timestamps |
| `/run/egress-resolver/metrics/egress-resolver.prom` | `apply` | node-exporter textfile |
| `/run/flashbox-endpoints/hosts` | `apply` | container `/etc/hosts` target |

All paths are overridable with command line options (`egress-resolver --help`).

## Development

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo run -- check-config --config examples/egress-resolver.toml
cargo run -- resolve --config examples/egress-resolver.toml --answers /tmp/answers.json
```

The `apply` step can be exercised without root in a throwaway namespace:

```
unshare -Urn bash -c '
  iptables -N DYN_BNET_PRODUCTION_OUT; iptables -N DYN_BNET_MAINTENANCE_OUT
  target/debug/egress-resolver apply --config examples/egress-resolver.toml \
     --answers /tmp/answers.json --hosts /tmp/hosts --status /tmp/status.json \
     --metrics /tmp/egress.prom --state-file /tmp/state --lock /tmp/lock
  iptables -S DYN_BNET_PRODUCTION_OUT'
```

## Security notes

* No searcher-controlled input is ever parsed: the only network peer is the
  configured resolver over authenticated TLS; the only files read are part of
  the measured image or written by this tool.
* `resolve` runs without capabilities and may only open TCP/853 to the
  configured resolvers (enforced by a uid-scoped host firewall rule);
  `apply` runs with `CAP_NET_ADMIN` and never touches the network.
* Addresses in loopback, link-local, private, shared, multicast, reserved and
  documentation ranges are rejected before they can reach the firewall.
* Trust delta for an auditor of the image: the resolver's DNSSEC validation
  delivered over TLS, and control of the endpoints' DNS zones.
