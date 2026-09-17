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

Two subcommands, run as two `Type=oneshot` systemd units (`egress-resolver.service`
for `resolve`, `egress-resolver-apply.service` for `apply`; the timer starts the
apply unit, which pulls in the resolve unit first) every minute:

1. **`resolve`** (unprivileged, no capabilities) queries every configured name
   for `A` records over DNS-over-TLS, trying the configured resolvers in order
   and all unsettled names concurrently on each. An answer is accepted only if
   the resolver set the AD bit (DNSSEC-validated), the response is not
   truncated, and the `A` records are owned by the queried name or by the end
   of a CNAME chain starting at it; every address must be global unicast IPv4.
   Authenticated NXDOMAIN/NODATA is an *empty* result; SERVFAIL, timeouts and
   TLS failures are *transient* and retried; a missing AD bit or a non-global
   address is *transient* but not retried on the same resolver. The whole run
   is bounded by `resolver.deadline_secs` (30 s): every answer is recorded the
   moment it arrives, and only the names still unsettled at the deadline are
   reported as transient. The result is written to `answers.json`; the command
   always exits 0. Note that with `require_authenticated` a name whose CNAME
   chain ends in an unsigned zone never gets a fresh answer (the resolver
   cannot set the AD bit), so it stays on last-known-good addresses for the
   rest of the boot; the zone owner has to keep every hop signed.
2. **`apply`** (`CAP_NET_ADMIN`, no IP sockets) takes the toggle lock and:
   * ignores answers that are missing, corrupt, older than three intervals, or
     already applied (same generation time as the last applied answers, i.e.
     the resolve step produced nothing new), treating every name as
     transient; the file is opened without following symlinks;
   * reads the two dynamic chains back from the kernel (`iptables -S`); the
     `--comment` on each rule records which name produced the address, so the
     kernel is the only state and the tool is stateless. A chain holding
     anything but one rule per address (a duplicate, a rule that is not ours)
     is rewritten even if its addresses already match;
   * computes the new production set (fresh answers; last-known-good addresses
     for transient names; nothing for empty names) and the maintenance set
     (everything ever resolved since boot, never shrinking);
   * replaces both chains atomically with `iptables-restore -n`, then reads them
     back and requires them to equal the plan (rule for rule); on any failure
     the previous policy stays and everything below describes *that* policy;
   * renders the hosts file from the installed addresses;
   * deletes conntrack entries by destination for flows that must not exist in
     the current mode (production: retired addresses; otherwise: every known
     address); `conntrack -D` exiting 1 counts as success only when it reports
     `0 flow entries have been deleted`, since operational errors exit 1 too;
   * writes `status.json` (consumed by `toggle` before entering production) and a
     Prometheus textfile, then exits non-zero if the firewall, hosts or
     conntrack step failed. Two values are carried from one run to the next
     through the previous `status.json` of the same boot: `last_fresh_uptime_secs`
     per name, which tells a reader how long an endpoint has been running on
     last-known-good addresses, and `applied_answers_uptime_secs`, the
     generation time of the last applied answers, which is what the
     already-applied check compares against.

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
| `/run/egress-resolver/status.json` | `apply` | mode, per-name state, `apply_ok` / `hosts_ok` / `conntrack_ok`, `required_satisfied`, `required_fresh`, `last_fresh_uptime_secs` per name, `applied_answers_uptime_secs`, `killed` / `kill_failed`, errors; uptime-based timestamps |
| `/run/egress-resolver/metrics/egress-resolver.prom` | `apply` | node-exporter textfile |
| `/run/flashbox-endpoints/hosts` | `apply` | container `/etc/hosts` target |

All paths are overridable with command line options (`egress-resolver --help`).

## Development

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo run -- check-config --config examples/egress-resolver.toml
cargo run -- print-servers --config examples/egress-resolver.toml   # for firewall-config
cargo run -- resolve --config examples/egress-resolver.toml --answers /tmp/answers.json
```

`check-config` is meant to run at image build time: `firewall-config` derives
the resolver allowlist from the same file with `print-servers`, so a broken
configuration must fail the build rather than the boot.

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
  configured resolvers (enforced by a uid-scoped host firewall rule and the
  unit's `RestrictAddressFamilies`); `apply` runs with `CAP_NET_ADMIN` in a
  unit whose `RestrictAddressFamilies=AF_NETLINK AF_UNIX` makes IP sockets
  impossible, not merely unused.
* `apply` trusts the addresses `resolve` hands it beyond checking that they are
  global unicast: the DNS step is part of what authorises egress, which is why
  it parses only the pinned resolvers' TLS-authenticated answers. `CAP_NET_ADMIN`
  itself is not confined to the two chains; the tool's own code is.
* Addresses in loopback, link-local, private, shared, multicast, reserved and
  documentation ranges are rejected before they can reach the firewall.
* Trust delta for an auditor of the image: the resolver's DNSSEC validation
  delivered over TLS, and control of the endpoints' DNS zones.
