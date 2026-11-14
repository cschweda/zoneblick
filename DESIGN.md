# zoneblick — High-Level Design

**Author:** Christopher Schweda · **Date:** 2026-11-13 · **Status:** Draft v0.2 (adds deep checks) · License question settled · `SVC` group proposed 2026-11-14

> *zoneblick* — *zone* + German *Blick* (a look, a glance). A self-hosted watchdog for DNS zones.

---

## 1. Summary

zoneblick is a single-binary, self-hosted DNS auditor. It resolves each of your zones from the root, asks **every authoritative nameserver directly**, checks the answers for correctness and risk, stores each run as a snapshot, and tells you what changed since the last one.

It combines three jobs that today live in separate tools:

1. **Correctness** — delegation, nameserver consistency, DNSSEC (the Zonemaster / DNSViz job).
2. **Exposure** — dangling records and subdomain-takeover risk (the BadDNS / dnsReaper job).
3. **Drift over time** — what changed, when, and on which server (the paid-SaaS job).

It is not a hosted service. You run your own instance; anyone else can run theirs with one binary and one config file.

## 2. Goals and non-goals

### Goals

- **One binary, one config file, one SQLite file.** No external database, queue, or runtime.
- **Authoritative-first.** Never trust a recursive resolver's cache; walk the delegation and query each nameserver over UDP and TCP, IPv4 and IPv6.
- **Fleet-oriented.** Built for tens to low hundreds of zones, checked on a schedule.
- **Diffable history.** Every run is a snapshot; every change is attributable to a run and a server.
- **Low-noise alerts.** Distinguish real drift from round-robin, geo-DNS, and CDN churn.
- **Easy to deploy anywhere.** A droplet, a VPS, a homelab box, a Raspberry Pi.
- **Useful without the daemon.** `zoneblick check example.org` works as a one-shot CLI and in CI.

### Non-goals

- **Not a hosted or multi-tenant service.** Single operator, single instance.
- **Not a DNS management tool.** It never writes records (that is dnscontrol / OctoDNS territory).
- **Not an offensive tool.** It detects dangling records; it never attempts to claim a resource. No brute-force subdomain enumeration by default.
- **Not a resolver or uptime monitor.** It does not serve DNS or measure query latency from many regions.
- **Not a replacement for Zonemaster's or DNSViz's full analysis.** v1 covers the checks that most often break real zones. A later deep-check phase (section 5) adds selected depth where history makes a check more useful. Full parity is not a goal.

## 3. Prior art and differentiation

| Tool | Strength | What it lacks for this use |
|---|---|---|
| Zonemaster, DNSViz | Deep delegation and DNSSEC analysis | One zone, one shot; no history, no fleet view, no takeover checks |
| BadDNS, dnsReaper | Takeover signatures (CNAME, NS, MX, SPF) | Security-scan framing; Python; no correctness checks or drift |
| dns-monitor (PyPI) | Baseline + policy checks | Provider-API based rather than authoritative-first; small scope |
| DNS Spy, ZoneWatcher and similar | Per-nameserver comparison, change alerts | Hosted SaaS, paid, your zone data on someone else's server |
| dnscontrol, OctoDNS | Desired-state management | Compare config to provider, not to what the internet actually sees |

**zoneblick's position:** the integration, self-hosted. No single open-source tool does correctness + exposure + drift in one deployable binary. The differentiation is honest but narrow — it is integration and packaging, not a new technique. That is acceptable; the engineering depth (iterative resolution, DNSSEC validation, noise-resistant diffing) is the point of the project.

## 4. Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │                zoneblick (one binary)          │
                    │                                              │
  zoneblick.toml ──► │  Scheduler ──► Run orchestrator               │
                    │                    │                          │
                    │        ┌───────────┼───────────────┐          │
                    │        ▼           ▼               ▼          │
                    │   Discovery   Resolver core    Check engine   │
                    │   (seeds, CT, (iterative, per- (rules over    │
                    │    AXFR, API)  server queries)  observations) │
                    │        │           │               │          │
                    │        └───────────┼───────────────┘          │
                    │                    ▼                          │
                    │              SQLite store                     │
                    │       (snapshots, findings, history)          │
                    │            │              │                   │
                    │            ▼              ▼                   │
                    │        Diff engine    Alert sinks             │
                    │            │        (email, webhook, ntfy)    │
                    │            ▼                                  │
                    │     HTTP API (axum) ──► Embedded web UI       │
                    └──────────────────────────────────────────────┘
                              ▲                       ▲
                          CLI (same binary)      reverse proxy (TLS)
```

### Components

- **Resolver core.** zoneblick's own iterative resolver: starts at the root hints, follows referrals, records the full delegation path, then queries each authoritative server for each name/type. Built on `hickory-proto` for wire format; the iteration logic is custom because the tool needs the *intermediate* answers (referrals, glue, per-server differences) that a normal resolver hides.
- **Discovery.** Builds the list of names to check per zone: seed names from config, zone transfer (AXFR) when permitted, Certificate Transparency logs, and optional provider API import (DigitalOcean, Cloudflare, Route 53).
- **Check engine.** Pure functions over stored observations. Each check has a stable ID (`DEL-01`, `SEC-03`…), a severity, and structured evidence. Checks never do network I/O themselves — that keeps them testable against recorded fixtures.
- **Store.** SQLite via `rusqlite`, WAL mode. Content-addressed RRsets so unchanged data costs nothing.
- **Diff engine.** Compares the latest snapshot to the previous one and to a pinned baseline.
- **Alert sinks.** Email (SMTP), generic webhook, ntfy. Alerts fire on finding *state changes*, not on every run.
- **HTTP API + web UI.** `axum` serves a JSON API and the embedded UI.
- **CLI.** Same binary: `check`, `serve`, `run`, `diff`, `zones`, `export`.

### Stack

| Layer | Choice | Notes |
|---|---|---|
| Core | Rust, `tokio` | Async UDP/TCP at fleet scale with bounded concurrency |
| DNS wire | `hickory-proto` | Parsing and serialization only; iteration is custom |
| DNSSEC | `hickory-proto` DNSSEC types + `ring` | Validation logic is custom; see Risks |
| HTTP | `axum` | API and static asset serving |
| Storage | SQLite (`rusqlite`, bundled) | One file, no external DB |
| Web UI | Nuxt 4 + Nuxt UI v4, `nuxt generate` (static SPA), pnpm | Built once, embedded in the binary with `rust-embed`. **As built (2026-11-13):** a single plain HTML and JavaScript page, the demo design wired to the API, compiled in with no build step; a Nuxt rewrite stays possible |
| Config | TOML | Single `zoneblick.toml` |

### Where the default stack fits and where it does not

**Flag:** the usual Nuxt-on-Netlify approach does **not** fit the backend. zoneblick needs raw UDP/TCP sockets on port 53 outbound, a long-running scheduler, and a persistent SQLite file. None of that works in serverless functions. The backend is Rust on a server.

Nuxt and Nuxt UI still fit the **front end**: the UI is generated as a static SPA and compiled into the binary, so the "one binary" promise holds and the UI stack stays familiar. The project landing page is separate, fully static, and can live on GitHub Pages.

## 5. Check catalog

Severity levels: **critical** (exploitable or outage now), **warning** (will break or is risky), **notice** (hygiene), **info**.

### Delegation (`DEL`)

| ID | Check | Severity |
|---|---|---|
| DEL-01 | Parent NS set differs from child NS set | warning |
| DEL-02 | Lame delegation: listed NS is not authoritative for the zone | critical |
| DEL-03 | Glue at parent differs from the address the NS name resolves to | warning |
| DEL-04 | Fewer than two nameservers, or all in one /24 or /48 | notice |
| DEL-05 | NS target is a CNAME | warning |
| DEL-06 | NS hostname's own domain is unregistered or expired | critical |

### Consistency (`CON`)

| ID | Check | Severity |
|---|---|---|
| CON-01 | SOA serial differs across authoritative servers | warning |
| CON-02 | RRset differs across authoritative servers for the same name/type | warning |
| CON-03 | Server does not answer over TCP | warning |
| CON-04 | Server unreachable over IPv6 (AAAA published, no answer) | notice |
| CON-05 | Server truncates without EDNS support or mishandles EDNS | notice |

### DNSSEC (`SEC`)

| ID | Check | Severity |
|---|---|---|
| SEC-01 | DS at parent, no matching DNSKEY at child (zone is bogus) | critical |
| SEC-02 | RRSIG expired, or expires within N days (default 7) | critical / warning |
| SEC-03 | DNSKEY present, no DS at parent (signed but not chained) | notice |
| SEC-04 | Weak or deprecated algorithm / digest (e.g. SHA-1 DS) | warning |
| SEC-05 | Signatures differ or are missing on some servers | warning |

### Mail and policy (`POL`)

| ID | Check | Severity |
|---|---|---|
| POL-01 | SPF exceeds 10 DNS lookups, or multiple SPF records | warning |
| POL-02 | No DMARC record, or policy `p=none` | notice |
| POL-03 | No CAA record | notice |
| POL-04 | MTA-STS record and policy file disagree, or policy unreachable | warning |
| POL-05 | MX target is a CNAME or does not resolve | warning |

### Takeover exposure (`TKO`)

| ID | Check | Severity |
|---|---|---|
| TKO-01 | CNAME target does not resolve (NXDOMAIN) | warning |
| TKO-02 | CNAME points to a known-claimable service and matches its "unclaimed" signature | critical |
| TKO-03 | CNAME / MX / NS target's registrable domain is available for registration | critical |
| TKO-04 | SPF `include:` or `redirect=` names an unregistered domain | critical |
| TKO-05 | Wildcard record resolving to a third-party service | notice |

Takeover signatures are **imported, not invented** — the community sets from Nuclei templates, dnsReaper and BadDNS are far better maintained than anything a new project could produce. See Risks for the licensing question this raises.

### Deep checks (post-v1)

The v1 catalog above is 26 checks. This second tier adds 14 more, borrowed in spirit from Zonemaster and DNSViz.

**Selection rule:** a deep check is added only if its result *changes over time* in a way an operator would want to be told about. Zonemaster and DNSViz can say a zone is wrong now; zoneblick's advantage is saying when it became wrong. Static facts about a zone that rarely change are left to those tools.

#### DNSSEC, deeper (`SEC`, continued)

| ID | Check | Severity |
|---|---|---|
| SEC-06 | Denial of existence: NSEC/NSEC3 proof missing or invalid for a name that does not exist | warning |
| SEC-07 | NSEC3 parameters: iterations above 0 or a salt in use (RFC 9276 guidance) | notice |
| SEC-08 | Key rollover state: DNSKEY set changed since the last run; DS without a matching key, or old key withdrawn too early | warning |
| SEC-09 | CDS / CDNSKEY records inconsistent across servers, or not matching the DNSKEY set | warning |
| SEC-10 | Algorithm completeness: an algorithm present in the DS or DNSKEY set has no signatures over some RRsets | warning |

#### Nameserver behaviour (`NSB`)

| ID | Check | Severity |
|---|---|---|
| NSB-01 | EDNS compliance: wrong or no response to EDNS queries, unknown EDNS versions or unknown options | warning |
| NSB-02 | Zone transfer (AXFR) allowed to arbitrary clients | warning |
| NSB-03 | Recursion available on an authoritative server | warning |
| NSB-04 | Query name case not preserved in the response | notice |

#### Network (`NET`)

| ID | Check | Severity |
|---|---|---|
| NET-01 | All nameservers are in one network (ASN) | notice |
| NET-02 | A nameserver address is in private or reserved space | warning |

#### SOA sanity (`SOA`)

| ID | Check | Severity |
|---|---|---|
| SOA-01 | Timers outside sane ranges (refresh, retry, expire, negative-caching TTL) | notice |
| SOA-02 | Primary named in the SOA (MNAME) is unreachable, or is not a listed nameserver | notice |
| SOA-03 | Contact mailbox in the SOA (RNAME) is at a domain that does not accept mail | notice |

SOA-02 is a notice because a hidden primary is a legitimate design; it can be muted per zone.

#### Explicitly out of scope

- Full Zonemaster parity (its profile system and complete test-case catalog).
- Hostname and label syntax checks, which rarely change and rarely cause incidents.
- Competing on one-shot forensic depth for a single zone.

### Run levels

Deep checks cost more queries per zone, so runs come in two levels.

| Level | Default cadence | Checks | Notes |
|---|---|---|---|
| **Light** | Hourly | DEL, CON, SEC-01 to SEC-05, POL, TKO | The fleet sweep. Unchanged from v1. |
| **Deep** | Daily, or on demand | Everything in Light, plus SEC-06 to SEC-10, NSB, NET, SOA | Adds probe queries per server: nonexistent-name lookups, EDNS probes, one AXFR attempt. |

```toml
[schedule]
every = "1h"      # light runs
deep  = "24h"     # deep runs; set to "off" to disable
```

`zoneblick check example.org --deep` runs the deep level once from the command line. A zone's "Run deep check now" button does the same from the UI.

Deep-run findings follow the same lifecycle as light ones (open, resolved, muted) and appear in the same list, tagged with the run level that produced them. A deep finding is only resolved by a later deep run.

### Proposed: HTTPS records and Encrypted Client Hello (`SVC`)

**Status:** proposed 2026-11-14, not built. Written against the code as of 0.14.0.

#### What exists already

Since 0.13.0 a run asks every ordinary name for its HTTPS record, and underscore names for SVCB. The records are stored, compared between nameservers and between runs, and have their signatures checked in a deep run. TKO-06 flags one whose target does not exist.

So two things need no new check: an HTTPS record that differs between nameservers (CON-02) and one that changed since the last run (drift).

#### What is missing

Nothing reads what is inside the record. An HTTPS record carries parameters that a browser acts on before it connects: address hints, the protocols on offer, a port, and the Encrypted Client Hello (ECH) configuration. Each of them can disagree with the rest of the zone or with the server, and the site still loads, because clients fall back.

ECH is the case that fits zoneblick best. The server rotates its ECH keys while resolvers still hold the old configuration from DNS. A mismatch appears over time and nobody is told, which is what the selection rule above asks for.

#### Checks

| ID | Check | Severity | Run level |
|---|---|---|---|
| SVC-01 | Address hints (`ipv4hint`, `ipv6hint`) differ from the A and AAAA records of the record's target | warning | light |
| SVC-02 | A record set mixes alias-mode and service-mode records, or has more than one alias-mode record | notice | light |
| SVC-03 | `mandatory` names a parameter the record does not carry, or the record breaks another RFC 9460 rule | warning | light |
| SVC-04 | The `ech` parameter does not parse as an ECH configuration list, or holds no version the checker knows | warning | light |
| SVC-05 | The record offers `h3` and the server's `Alt-Svc` header does not, or the reverse | notice | deep |
| SVC-06 | A TLS handshake that offers ECH with the published configuration is rejected by the server | warning | deep |
| SVC-07 | The port or target in a service-mode record does not accept a TLS connection | warning | deep |

A name with no HTTPS record gets no finding. Most zones have none, and that is not a fault.

SVC-06 is the one with no equivalent elsewhere in the tool. When a server cannot decrypt the inner hello it finishes the handshake under its public name and hands back fresh configurations. The check reports that outcome, with the public name and the age of the record, so the fix is clear: publish the current configuration.

#### What it needs

- **DNS parsing.** `hickory-proto` 0.26, already a dependency, parses SVCB and HTTPS parameters, including the ECH configuration list as wire-format bytes. Confirmed against its documentation on 2026-11-14.
- **ECH handshake.** `rustls` 0.23, already a dependency, has client-side ECH: a configuration is built from the list in DNS and switched on in the client config. Confirmed against its documentation on 2026-11-14.
- **HPKE.** rustls needs an HPKE implementation to encrypt the hello. zoneblick builds rustls with the `ring` provider; whether that is enough, or ECH needs the `aws-lc-rs` provider or a separate HPKE crate, is **not yet confirmed** and is a new-dependency decision for the owner. See open question 6.
- **Connections.** SVC-05 to SVC-07 open a connection to the zone's own web server. They follow the same limits, deadlines and private-address rules as the existing certificate and mail connections.

#### Build order

1. **SVC-01 to SVC-04.** Rules over records the store already holds. No new dependency and no new connection.
2. **SVC-05 and SVC-07.** Use the HTTP and TLS clients already in the build.
3. **SVC-06.** After the HPKE decision. Tests need a zone that publishes ECH; recorded fixtures cover the rejected case.

#### Out of scope

- A QUIC connection to prove HTTP/3 works. That needs a QUIC client and belongs in a separate tool.
- GREASE ECH, and anything about serving or publishing ECH configurations.
- A finding for "this zone could use ECH and does not".

## 6. Data model and drift

### Tables (sketch)

- `zones` — name, config hash, enabled, schedule.
- `names` — zone, FQDN, discovery source, first/last seen, `volatile` flag.
- `runs` — id, started/finished, trigger (schedule / manual / CLI), **level (light / deep)**, status, stats.
- `rrsets` — content-addressed: hash → canonical RRset (name, type, sorted rdata). TTL stored separately so TTL changes do not create new hashes.
- `observations` — run, name, type, **server**, transport, rcode, flags, rrset hash, RRSIG metadata.
- `findings` — check ID, zone, name, severity, evidence JSON, **fingerprint**, first seen, last seen, state (`open` / `resolved` / `muted`).
- `baselines` — a pinned run per zone that means "this is correct".

### Drift detection

A **change** is a difference in the set of RRset hashes for a (name, type) between two runs. Reported as added / removed / modified, per server.

Noise control, in order:

1. **Canonicalize.** Sort rdata, lowercase names, ignore TTL countdown.
2. **Compare as sets across servers first.** If every server returns a different rotation of the same pool, that is not drift.
3. **Volatility learning.** A name whose answers flap across N consecutive runs is marked `volatile`; it is tracked but alerts only when the *pool* changes (e.g. a new ASN or a CNAME target change), not when membership rotates.
4. **Ignore rules.** Per-zone patterns in config (`ignore = ["_acme-challenge.*"]`).
5. **Alert on state transitions only.** A finding that stays open does not re-alert; it appears in a periodic digest.

### Retention

Observations are compact because RRsets are deduplicated. Default: keep every run for 30 days, then one run per day for a year. Findings history is kept indefinitely.

## 7. Interfaces

### CLI

```
zoneblick check example.org            # one-shot, human output, exit code by severity
zoneblick check example.org --json     # machine output for CI
zoneblick check example.org --deep     # include the deep checks
zoneblick serve                        # daemon: scheduler + API + UI
zoneblick run [--zone example.org]     # trigger a run against the running store
zoneblick diff example.org [--from RUN --to RUN]
zoneblick zones list | add | remove
zoneblick export --format json|csv
```

`check` needs no config file and no database. It is the first thing built and the easiest way for someone to try the tool.

### Web UI

- **Overview** — zones, open findings by severity, last run, recent changes.
- **Zone detail** — findings, nameserver matrix (each server × transport × SOA serial), delegation path.
- **DNSSEC chain view** — a per-zone diagram of the DS → DNSKEY → RRSIG chain from the root down, with each link marked valid, expiring or broken. Any two runs can be compared, which shows a key rollover before and after.
- **Links out** — DNSSEC and delegation findings link to the same zone in DNSViz and Zonemaster for a closer look.
- **History** — run timeline with a record-level diff between any two runs.
- **Settings** — read-only view of effective config (config stays in the TOML file; the UI does not edit it in v1).

### API

JSON over HTTP under `/api/v1`: `zones`, `runs`, `findings`, `diff`, `health`. Token auth. The UI uses the same API.

### Alerts

Email, webhook (generic JSON, suitable for Slack/Discord/Teams relays), and ntfy. Each alert names the check ID, the zone, the server(s) involved, and the before/after values.

## 8. Deployment

### Config

```toml
[server]
bind = "127.0.0.1:8053"
data_dir = "/var/lib/zoneblick"

[schedule]
every = "1h"
max_qps_per_server = 5

[[zone]]
name = "example.org"
seeds = ["www", "api", "mail"]
discover = ["ct", "axfr"]
ignore = ["_acme-challenge.*"]

[alerts.email]
to = "ops@example.org"
```

### Your own instance (DigitalOcean droplet)

1. Download the release binary (static musl build, x86_64).
2. Place `zoneblick.toml` in `/etc/zoneblick/`.
3. Run as a daemon — a Forge-managed daemon or a plain systemd unit, running as an unprivileged `zoneblick` user.
4. Put it behind the existing nginx with TLS on a subdomain; the app binds to localhost only.
5. Enable IPv6 on the droplet so the IPv6 reachability checks mean something.

Resource needs are small: a few hundred names hourly is a few thousand queries per run, well within the smallest droplet.

### The easy path for anyone else

Three supported routes, in order of effort:

1. **Install script** — `curl … | sh` fetches the right binary, creates the user, writes a starter config and a systemd unit. Works on any Linux server.
2. **Docker** — one image, one volume for `/data`, one mounted config file. A sample `compose.yaml` ships in the repo.
3. **Manual** — download binary, write config, run `zoneblick serve`.

Release artifacts: static binaries for Linux x86_64 and aarch64 (covers droplets and Raspberry Pi), macOS builds for trying the CLI, and a multi-arch container image, all built by GitHub Actions on tag.

Design rules that keep deployment easy:

- No required environment variables; everything in one TOML file.
- No external services required to start; alerts are optional.
- Upgrades are "replace the binary"; schema migrations run on startup.
- `zoneblick check` works with zero setup, so people can evaluate before deploying.

### Project site

A static landing page and a demo page with sample data, hosted on GitHub Pages from the repo's `docs/` folder. No build step.

## 9. Security and responsible use

- **Scan only what you control.** Documentation and the default config say so plainly. There is no "scan any domain" form in the UI.
- **Polite by default.** Per-server QPS cap, bounded concurrency, exponential backoff, and a clear identifying pattern in query behavior (no spoofing, no randomization tricks).
- **Passive detection only.** Takeover checks read DNS and, where a signature requires it, make one HTTP GET. zoneblick never registers, claims, or uploads anything.
- **No brute-force enumeration by default.** Discovery uses seeds, CT logs, AXFR, and provider APIs.
- **Deep probes stay small.** A deep run adds a handful of queries per nameserver and a single AXFR attempt. The AXFR check records only whether the transfer was permitted; it does not store transferred records unless AXFR discovery is enabled for that zone.
- **Local-first exposure.** Binds to localhost; remote access goes through a reverse proxy with TLS. Single admin token, stored hashed.
- **Secrets.** Provider API tokens and SMTP credentials are read from the config file or a separate secrets file with `0600` permissions; never logged, never returned by the API.
- **The store is sensitive.** A list of dangling records is a list of attack opportunities. The data directory is owner-only, and exports are explicit.

## 10. Build phases

| Phase | Deliverable | Proves |
|---|---|---|
| 0 | `zoneblick check <zone>`: iterative resolution, per-server queries, DEL and CON checks, terminal output | The resolver core works |
| 1 | SQLite store, snapshots, `diff` command | The data model and noise control work |
| 2 | DNSSEC checks (SEC) | The hardest correctness logic |
| 3 | `serve`: scheduler, API, alerts | It runs unattended |
| 4 | Embedded web UI | It is pleasant to live with |
| 5 | POL and TKO checks, signature import, CT discovery | Full v1 check catalog |
| 6 | Packaging: install script, Docker image, release pipeline, docs | Anyone can deploy it |
| 7 | Deep checks (v1.1): deep run level, SEC-06 to SEC-10, NSB, NET, SOA | Depth where history adds value |

Phase 0 is useful on its own and is the natural first milestone.

The DNSSEC chain view and the DNSViz / Zonemaster links ship with the web UI in Phase 4, because they only need data that Phase 2 already collects. The deep checks themselves wait until after v1 is released.

**Testing approach:** record real DNS exchanges as fixtures and replay them, so checks are tested offline and deterministically. Maintain a small set of deliberately broken test zones (lame delegation, expired signatures, serial mismatch) for end-to-end runs.

## 11. Risks and open questions

### Risks

- **DNSSEC validation is easy to get subtly wrong.** NSEC/NSEC3 denial proofs, wildcard expansion, and algorithm rollover states are all sharp edges. Mitigation: validate against DNSViz results on known-good and known-broken zones; ship SEC checks behind a "beta" label first.
- **False positives on takeover.** Signatures go stale as providers change their error pages. Mitigation: confidence levels (confirmed / likely / possible), and import signatures rather than fork them.
- **Signature licensing.** dnsReaper is AGPL-3.0 and BadDNS is GPL-3.0; Nuclei templates are MIT. Bundling GPL-family signature data may constrain zoneblick's own license. Options: (a) fetch signatures at runtime from upstream instead of bundling, (b) use only the MIT-licensed set, (c) license zoneblick compatibly. **Needs a decision before Phase 5.** As built in 0.6.0: option (b), the MIT-licensed Nuclei set only, bundled; see DECISIONS.md.
- **Drift noise.** If the first week produces fifty alerts about CDN rotation, people will turn it off. The volatility logic needs real-world tuning against actual zones before the alerting phase ships.
- **Scope creep toward Zonemaster parity.** The v1 catalog is deliberately 26 checks, and the deep tier adds 14. Any further check has to pass the selection rule in section 5: its result must change over time in a way worth an alert.
- **Deep DNSSEC checks raise the validation risk.** Denial-of-existence proofs and rollover-state logic are the hardest parts of DNSSEC to get right. They ship behind a beta label and are compared against DNSViz on known-good and known-broken zones before they can raise alerts.
- **Probe queries can look hostile.** EDNS probes with unknown versions and an AXFR attempt may trip intrusion detection on some hosts. Deep runs are opt-out per zone and identify themselves consistently.

### Open questions

1. ~~**License** — MIT, Apache-2.0, or GPL-family (tied to the signature question above)?~~ **Settled 2026-11-13:** dual-licensed MIT or Apache-2.0, the usual choice for Rust projects. This rules out option (c) under "Signature licensing"; GPL-family signature data cannot be bundled, so Phase 5 must use option (a) or (b).
2. **Multiple vantage points** — is a second probe (e.g. another region) worth supporting later for geo-DNS zones, or out of scope?
3. **Provider API import** — which provider first? DigitalOcean is the obvious one for the reference deployment.
4. **UI config editing** — keep config file-only, or allow adding zones from the UI in a later version?
5. **ASN data for NET-01** — look up network ownership over DNS at run time (for example Team Cymru's IP-to-ASN service), or ship an offline table that is refreshed with releases?
6. **HPKE for the ECH check (SVC-06)** — can rustls do ECH with the `ring` provider this build uses, or does the check need the `aws-lc-rs` provider or a separate HPKE crate? Either is a new direct dependency and needs the owner's approval.
7. **Name checks** — zoneblick.com was registered on 2026-11-13. A web search found no project using the name. Trademark, crate and GitHub names still need checking.

---

## References

- Zonemaster — https://zonemaster.net
- DNSViz — https://dnsviz.net
- BadDNS — https://github.com/blacklanternsecurity/baddns
- dnsReaper — https://github.com/punk-security/dnsReaper
- dns-monitor — https://pypi.org/project/dns-monitor/
- DNS Spy — https://dnsspy.io
- Hickory DNS — https://github.com/hickory-dns/hickory-dns
- RFC 9460, SVCB and HTTPS records — https://www.rfc-editor.org/rfc/rfc9460
- rustls client ECH configuration — https://docs.rs/rustls/latest/rustls/client/struct.EchConfig.html
