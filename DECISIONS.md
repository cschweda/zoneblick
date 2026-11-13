# Decisions

Choices made during implementation where `DESIGN.md` was silent or loose. One line each.

## Phase 0

- Politeness defaults beyond the design's 5 queries per second per server: 16 queries in flight, 3 s UDP and 5 s TCP timeouts, 2 retries after 0.5 s and 1 s (agreed with the author).
- The per-server rate cap is per IP address, not per nameserver hostname.
- Only timeouts are retried; a network error such as "connection refused" is final.
- No `rand` dependency after all: `hickory_proto::op::Message::query()` already picks a random message ID.
- EDNS queries advertise a 1232-byte UDP payload.
- The resolver asks one server per zone on the way down and moves to the next (at most four) only when one fails; IPv4 addresses are tried before IPv6.
- DEL-01's parent side is the referral from the one parent server that was asked, not a survey of all parent servers.
- DEL-01's child side is the union of the NS sets from all authoritative servers; disagreement between them is CON-02.
- DEL-02 also covers a listed nameserver that answers nothing (`no_response`) or whose name has no address (`unresolvable`), told apart from `not_authoritative` in the evidence (agreed with the author).
- A server counts as authoritative when any SOA query to it gets a NOERROR answer with the AA flag.
- A silent IPv6 address on a nameserver that answers over IPv4 is CON-04 only, not DEL-02.
- DEL-03 compares glue with resolved addresses per address family, and only for families the glue covers.
- DEL-04's network test runs per address family: all IPv4 addresses in one /24, or all IPv6 addresses in one /48.
- DEL-06 is a stub: it needs registry data (RDAP or WHOIS), which a check may not fetch.
- CON-02 covers the apex NS set and the SOA fields other than the serial, because Phase 0 queries nothing else.
- CON-03 fires when a server answers over UDP but gives no response to any TCP query.
- CON-04 is skipped when IPv6 does not work from the local machine (no root server answers over IPv6); one `info` finding reports the untested addresses (agreed with the author).
- CON-05 means: FORMERR, NOTIMP or BADVERS to an EDNS query; no OPT in the reply to an EDNS query; a UDP response over the allowed size; or TC over UDP with no TCP answer (agreed with the author).
- CON-05 judges only servers that are authoritative for the zone, so a lame server is not reported twice.
- Each nameserver address gets five queries: SOA and NS over UDP and TCP with EDNS, plus SOA over UDP without EDNS for CON-05.
- Nameservers listed only by the zone itself, not the parent, are resolved and probed too, in one extra round.
- `info` findings alone exit `0`.
- A name that is not a zone apex (for example `www.example.com`) is a failed run, exit `3`, and the error names the enclosing zone.
- A run in which no nameserver answers any query is a failed run, exit `3`, rather than a list of DEL-02 findings.
- A command-line usage error exits `3`, not clap's default `2`, because `2` means "critical finding".
- When an ancestor's servers answer for the zone themselves (the root zone, or parent and child on the same servers), there is no referral, so no parent view; DEL-01 and DEL-03 are skipped.
- `--record FILE` and `--replay FILE` were added to `check` as the record-and-replay layer; they are not in the design's CLI sketch.
- Fixtures store raw DNS wire bytes as hex, so a replay runs the same parsing code as a live run.
- `started_at_unix` is the only time-dependent field in the JSON; a replay takes it from the fixture.
- With `--json`, a failed run prints a short JSON error document on stdout instead of text on stderr.
- Names in observations and output are lowercase and fully qualified, with a trailing dot.
- The license is MIT or Apache-2.0, at the user's option, the usual Rust dual license (chosen by the author on 2026-11-13, settling open question 1 in the design).
- Release binaries are built by GitHub Actions on a version tag: static musl builds for Linux x86_64 and aarch64, macOS builds for both architectures and a 64-bit Windows build, none of them signed; the install script, Docker image and crates.io wait for the packaging phase.
- Releases below version 1.0 are published as GitHub pre-releases.
- The check modules are `delegation.rs` and `consistency.rs`, not `del.rs` and `con.rs`: `con` is a reserved file name on Windows and breaks a checkout there.
- Install commands in the README and on the site name an exact release, so they must be updated with each release (GitHub's "latest" link skips pre-releases).
- Rust edition 2024, which needs Rust 1.85; `hickory-proto` 0.26 needs 1.88.

## Phase 1

- Dependencies added with the author's agreement: `rusqlite` with bundled SQLite, and `sha2` for content hashes. Building from source now needs a C compiler.
- Names to check come from repeated `--name` flags on `run` and are remembered in the database; the TOML config file waits for the daemon phase (agreed with the author).
- Noise control in this phase is canonical record sets, comparison as pools across servers, and ignore patterns; volatility learning and pinned baselines wait for real run history (agreed with the author).
- `run` is a new storing command; `check` is unchanged and still stores nothing.
- The database defaults to `zoneblick.sqlite` in the current directory; `--db FILE` overrides it.
- A stored run asks for A, AAAA, CNAME, MX, TXT and CAA at every name (no CNAME at the apex), and takes the apex SOA and NS from the nameserver probes instead of asking again.
- Only nameserver addresses that answered a probe are asked for records; a dead server is already reported and would slow every run.
- Record queries go over UDP with EDNS and are retried over TCP when truncated.
- Record data is stored as canonical text: sorted, names lowercase and fully qualified, TXT strings quoted.
- A record set's content hash covers name, type and data, not TTL; the TTL is kept on each observation.
- A run that fails (exit code 3) is not stored.
- A diff compares pools: the union of what all authoritative servers served for a name and type. Disagreement between servers within one run is CON-02's job, not the diff's.
- Only authoritative NOERROR and NXDOMAIN answers count in a diff; NXDOMAIN is an empty set.
- A name checked in only one of the two runs is listed as not compared, not as added or removed.
- A TTL change is its own change kind and is not counted as a record change.
- A SOA whose only difference is the serial is shown on one line and does not make `diff` exit 1.
- Ignore patterns are given to `diff` with `--ignore`; they are not stored. `*` matches anything and the pattern must match the whole name.
- `diff` exits 0 for no changes, 1 for changes and 3 on failure.
- `run` exits with the same codes as `check`; changes since the last run do not affect its exit code.
- A finding's identity across runs (its fingerprint) is its check ID, name and a stable detail such as the server address; moving values such as serials are left out.
- A finding not seen in a run is marked resolved; seen again later, the same finding reopens.
- CON-02 also covers every record set `run` collects, comparing authoritative answers across servers; NXDOMAIN on one server and data on another counts as a difference.
- `--forget-name` was added so a remembered name can be dropped; its history stays in the database.
- `zones list` is the only `zones` action so far; zones are added by running them, not by a separate command.
- Retention (thinning old runs) is not implemented; every run is kept.
- The database layout version is kept in SQLite's `user_version`; a database from a newer zoneblick is refused.
- `DESIGN.md` now records the license decision: MIT or Apache-2.0.

## Phase 2

- `hickory-proto` stays without its DNSSEC feature (which would pull in a crypto library); DS, DNSKEY and RRSIG records are parsed from raw record data in `src/dnssec.rs`.
- The SEC checks read keys, DS records and signature dates; they do not verify signatures cryptographically yet. They are labelled beta in the README and on the site, as the design asks.
- A DS matches a DNSKEY when key tag and algorithm agree and the SHA-256 or SHA-384 digest is right; a SHA-1 or GOST DS is matched on key tag and algorithm only (and reported as weak by SEC-04).
- The DS set is read from the one parent server that gave the referral, with the DO bit set.
- Each responding nameserver address gets two more queries with the DO bit: DNSKEY and SOA. Both `check` and `run` collect DNSSEC data.
- SEC-01 is judged per server: a server whose DNSKEY set contains no key any DS points at is reported.
- SEC-02 measures time from the start of the run and looks at the signatures over the DNSKEY and SOA record sets.
- SEC-02 warns within seven days of expiry, or within a quarter of the signature's lifetime when that is shorter; found necessary because zones signed on the fly (for example by Cloudflare) carry signatures valid for only a day or two.
- SEC-02's identity as a finding is the covered record type, not the dates, so one expiring signature is one finding across runs.
- SEC-03 fires only when the parent positively answered "no DS"; a parent that did not answer proves nothing.
- SEC-04 follows RFC 8624: RSA/MD5, DSA, RSA/SHA-1 (with or without NSEC3) and GOST are weak, as are SHA-1 and GOST DS digests.
- SEC-05 compares, across servers, the DNSKEY key tags and which keys sign the SOA.
- An unsigned zone (no DS, no DNSKEY) produces no SEC findings.
- Queries carry a `dnssec` flag for the DO bit; it is left out of fixture files when false, so older fixtures still load.
- The database layout moved to version 2 (a `dnssec_json` column on runs); older databases are upgraded in place on open.
- The JSON report gained a `dnssec` field; `schema_version` stays 1 because fields were only added.
- The terminal output's clean message is now "All checks passed."

## Phases 3, 4 and 6

- Dependencies added with the author's agreement: `axum`, `toml`, `reqwest` and `lettre`. `rustls` is named directly as well, only to select the `ring` crypto provider, so no OpenSSL or aws-lc is needed and the static Linux builds still work.
- The web UI is the existing demo page wired to the API and compiled into the binary, not the Nuxt 4 app in the design (agreed with the author). No Node build step and no `rust-embed`.
- The UI gets its data from one endpoint, `GET /api/v1/ui`, shaped for the page.
- The UI loads nothing from other sites (no web fonts) and is served with a restrictive Content-Security-Policy.
- The config file is refused when it has unknown keys, so typos are reported.
- The API token is stored only as a SHA-256 hash (`token_sha256`); `zoneblick token` prints the config line for a token the user supplies. zoneblick does not generate tokens.
- A non-loopback `bind` without a token is refused at startup.
- Without a token the API answers only requests whose Host header is a loopback name, which blocks DNS rebinding.
- Requests that change something must send JSON and must not carry a cross-site Origin or Sec-Fetch-Site header.
- `GET /health` needs no token and returns only status and version.
- The daemon checks every zone at startup and then once per interval, one zone at a time.
- A zone's names in the daemon are its `seeds` plus any names remembered from `zoneblick run`.
- The `ignore` patterns of a zone apply to the daemon's change reports, alerts and the API's diff.
- An alert is sent when findings open or resolve, records change or the delegation changes; on a zone's first run every finding counts as new; `info` findings never alert.
- A failed run is logged and shown in the UI, not stored, and does not alert.
- Email alerts are built with `lettre` over STARTTLS by default; they have not been tested against a real mail server.
- The `deep` config key from the design is accepted and ignored for now.
- Packaging: `install.sh` (also served at zoneblick.com/install.sh) installs the newest release, pre-releases included, and verifies its checksum; as root on Linux with systemd it creates the user, config, data directory and service.
- The container image is built from the release's static binaries on `distroless/static` (no compiler in the image build, no emulation), runs as an unprivileged user, and is published to `ghcr.io/cschweda/zoneblick`.
- The project website uses Plausible analytics; the binary and its web UI send no telemetry.

## Phase 5

- Built first: POL-01 to POL-05, TKO-01, TKO-03 and TKO-04. Added in 0.6.0: DEL-06, TKO-02, TKO-05 and discovery from certificate logs, which completes the 26 checks of the v1 design.
- Mail and policy lookups go through the iterative resolver from the root, because SPF includes and alias targets live in other zones; no recursive resolver is used.
- "Unregistered" is decided from DNS alone: NXDOMAIN from a top-level domain's servers means the domain is not delegated. No registry (RDAP or WHOIS) lookup and no public-suffix list. Domains under two-level suffixes are therefore reported as dangling (TKO-01), not unregistered.
- TKO-03 covers CNAME and MX targets. A nameserver in an unregistered domain is DEL-06 only, decided the same way (NXDOMAIN from a top-level domain); only nameservers outside the zone that have no address are looked up.
- Signature licensing (the design's open question): option (b), the MIT-licensed set only. The page texts for TKO-02 are imported from nuclei-templates and bundled in `src/signatures.rs`, with the licence in `THIRD-PARTY.md`. Nothing is fetched at run time and no GPL-family data is used. This was chosen without asking, to finish v1; it is one file to replace if run-time fetching is preferred.
- TKO-02 uses only templates that match on body text and status, for eleven services, and only for aliases whose target lies under the service's own hosting domain (those domains are not in the templates; they are the services' published ones). One plain-HTTP GET of the hostname's front page, no redirects, at most twenty hostnames per run. No confidence levels yet.
- TKO-05 asks for `*.<zone>` by its literal name and reports a CNAME that leaves the zone. A wildcard A record is not reported: an address does not say whose it is.
- Certificate-log discovery reads crt.sh, is opt-in (`--discover ct`, or `discover = ["ct"]` once a day in the daemon) because it tells crt.sh the zone, adds at most 200 names, and skips wildcards. A failed lookup does not fail the run. A forgotten name comes back if discovery finds it again.

## Drift, continued (0.6.0)

- Volatility: an A or AAAA set that changed in each of three consecutive run-to-run steps is volatile. A later change is `rotation`, not counted and not alerted, when every new address was seen in the last ten runs or shares a /24 or /48 with one that was. This stands in for the design's "new ASN" test, since there is no ASN data. It is computed from stored runs at diff time; the `names.volatile` column is not used.
- Baselines: one pinned run per zone (`baselines` table, layout 4). `diff --baseline` compares it with the latest run; alerts still compare with the previous run only.
- Retention: the design's default (every run for 30 days, then the last run of each UTC day for a year). A zone's latest run and its baseline are never deleted; finding history is kept. `zoneblick prune` by hand, and the daemon after every round.
- Not built from the design's CLI list: `zones add | remove` and `export`; AXFR and provider-API discovery; muting a finding.
- A target that is unregistered is reported once, as TKO-03, not also as TKO-01 or POL-05.
- TKO-01 and the CNAME part of TKO-03 use the CNAME records `run` collects, so they need `run` or `serve`; the apex-level checks also run in `check`.
- SPF: every `include`, `redirect`, `a`, `mx`, `exists` and `ptr` counts as one lookup, includes are followed breadth-first to depth 10, and following stops after 30 lookups. When a zone has several SPF records the first is followed.
- An SPF domain containing a macro is counted but not resolved.
- POL-02 looks only at `_dmarc.<zone>`; it does not walk up to an organisational domain.
- POL-03 looks only at the zone apex.
- POL-04 fetches `https://mta-sts.<zone>/.well-known/mta-sts.txt` once, without following redirects, keeping at most 64 KB; this is the only HTTP request zoneblick makes for a check.
- HTTP fetches are part of fixtures, so MTA-STS is recorded and replayed like DNS.
- A lookup that failed (as opposed to "no such record") never produces a policy finding.
- The database layout moved to version 3 (a `policy_json` column on runs).
- The JSON report gained a `policy` field; `schema_version` stays 1.

## Release pipeline

- Every GitHub Action in the workflows is pinned to a full commit SHA, with the version in a comment, because the release job can publish releases and container images; Dependabot proposes updates monthly.
