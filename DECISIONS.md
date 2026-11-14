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

- Volatility: an A or AAAA set that changed in each of three consecutive run-to-run steps is volatile. A later change is `rotation`, not counted and not alerted, only when every address was already served in one of the last ten runs. An unseen address always counts, even in the same network: a neighbouring address can belong to someone else, so treating nearness as rotation would let a redirect pass silently (raised by a security review of 0.6.0, which did match on /24 and /48; fixed in 0.6.1). The design's "new ASN" test is not built, since there is no ASN data. It is computed from stored runs at diff time; the `names.volatile` column is not used.
- Baselines: one pinned run per zone (`baselines` table, layout 4). `diff --baseline` compares it with the latest run; alerts still compare with the previous run only.
- Retention: the design's default (every run for 30 days, then the last run of each UTC day for a year). A zone's latest run and its baseline are never deleted; finding history is kept. `zoneblick prune` by hand, and the daemon after every round.
- Added in 0.7.0: `zones add | remove`, `export`, AXFR discovery and muting.
- Muting: `findings mute` sets the stored state to `muted`, by fingerprint prefix. A muted finding is still stored with every run that sees it, but is left out of the run's report, exit code, diffs and alerts. It stays muted when it stops being seen; unmuting makes it open or resolved according to the latest run. There is no API or UI control for muting yet.
- `export` writes findings with their lifecycle (JSON or CSV), not record data; CSV cells that start like a formula are prefixed with an apostrophe.
- `zones remove` deletes without asking; `zones add` only stores the zone and names (the daemon's zones still come from the config file).
- AXFR discovery is a plain TCP transfer outside the record/replay client, so it is skipped when replaying. It runs after the checks, so names it finds are checked from the next run on. Owners of A, AAAA, CNAME, MX and TXT records only, at most 500.
- Not built: discovery from provider APIs (the design calls it optional).
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

## Phase 7: deep checks (0.8.0, partly)

- Built: SEC-07, SEC-09, SEC-10, NSB-01 to NSB-04, NET-02, SOA-01 to SOA-03. Not built: SEC-06 (denial proofs), SEC-08 (rollover state, which needs history inside a check), NET-01 (needs ASN data; the design's open question 5), and signature verification.
- A deep run is a light run plus the deep probes (`--deep`, or `[schedule] deep = "24h"`). Unlike the design, the daemon makes no deep runs unless `deep` is set: an upgrade should not start sending zone-transfer requests and odd EDNS queries by itself.
- The deep probes per responding nameserver: an SOA query with EDNS version 1, one with an unknown EDNS option (code 65001), one with RD set, one with the name in mixed case; NSEC3PARAM, CDS and CDNSKEY queries; one AXFR attempt of which only the first message is read. The AXFR attempt is live-only (not recorded or replayed).
- `QuerySpec` gained a `probe` field, left out of fixtures when plain, so existing fixtures still replay.
- Deep check IDs are flagged in the catalog. A light run carries a zone's open deep findings forward (their last-seen run moves on), so only a deep run resolves them and no diff reports them as resolved in between.
- SOA-01 uses loose limits (see the README), not Zonemaster's stricter defaults, which would flag every zone at some large providers.
- NET-02 treats documentation ranges as reserved, so test worlds on those ranges report it in deep runs.
- The deep probe data is in `check --json` and `run --json` under `deep`; it is not stored in the database, only the run's level and the findings are.

## Phase 7, continued (0.9.0)

- Added SEC-06 and SEC-08. Still not built: NET-01 (needs ASN data) and signature verification (needs a cryptography library as a direct dependency).
- SEC-06 asks each nameserver, with the DO bit, for `zz--zoneblick-absent.<zone>`. For a signed zone the answer must carry NSEC or NSEC3 records with a signature over them. NSEC records are checked for covering the name in canonical order, including the "name exists, no such type" form some providers answer with. NSEC3 proofs are not hashed and checked, and no signature is verified. A name that gets an answer (a wildcard) is skipped.
- SEC-08 compares the DNSKEY set (key tag and algorithm) with the zone's previous stored run of either level; the previous set is put into the observation before the checks run, so the check itself stays a pure function. A clean change is an `info` finding; a removed key that the parent's DS set still names, or that still signs the DNSKEY set or SOA, is a warning. A plain `check` has no previous run, so it never reports SEC-08.
- Names read out of record data are written with `\DDD` escapes for anything but hostname characters.

## Signature verification and NET-01 (0.10.0)

- `ring` is now a direct dependency (approved 2026-11-13); it was already in the build through rustls.
- SEC-11 (not in the design's catalog) reports a signature over the DNSKEY set or the SOA record that does not verify with a published key. It runs on every run and is critical, since validators treat such a zone as bogus. Verified: RSA with SHA-1, SHA-256 and SHA-512 (1024 bits and up), ECDSA P-256 and P-384, Ed25519. A signature whose algorithm is unknown or whose key is not published is "untried" and not reported. Verification happens when the answer is collected, where the raw records are; the check reads the stored verdict.
- Checked live: ECDSA P-256 on example.com and example.org, RSA/SHA-256 on the root zone. Ed25519 and ECDSA are also tested with keys made in the tests; P-384, RSA/SHA-512 and RSA/SHA-1 have no test.
- The offline test zones are now really signed (Ed25519 keys made from fixed seeds), so the signed fixtures verify.
- NET-01 uses Team Cymru's IP-to-ASN service over DNS (approved 2026-11-13; the design's open question 5), one TXT lookup per nameserver address in deep runs, through zoneblick's own resolver. It reports only when every address has a known origin and all share an ASN.
- All 14 deep checks of the design are now built.

## 0.11.0

- The API gained `POST /findings/mute`, `POST /findings/unmute` and `"deep": true` on `POST /runs`; the web UI has a Mute button per finding and a deep-check button for the selected zone. The UI file is now edited in `src/ui/index.html` directly; `docs/demo.html` does not have these controls.
- SEC-06 now checks NSEC3 proofs: for the probe name, one label below the apex, a record must match the apex hash and records must cover the hashes of the name and of the wildcard (or match the name, the "no such record" form). The hash is checked against the examples in RFC 5155. Zones with more than 2500 iterations or a hash other than SHA-1 are not judged. No live NSEC3 zone was checked: none of the permitted test zones uses NSEC3.
- Provider discovery: DigitalOcean only (`discover = ["digitalocean"]`), the design's first choice. The token comes from a file in the daemon and from `ZONEBLICK_DIGITALOCEAN_TOKEN` in the CLI; it is sent as a bearer token, redirects are not followed, and it is never recorded. Tested against recorded answers only; the response shape is from DigitalOcean's API documentation as I know it, not from a live call.
- No RSA signing test: it would need a private key in the repository. RSA verification is checked live against the root zone.

## 0.12.0

- Registration watch: RDAP, through IANA's bootstrap file and the registry's service, with no new dependency. It runs only in a deep run, because the registry learns that the domain was looked up, as crt.sh does for discovery. The registered domain is taken from the delegation path: the first zone below a top-level domain, then the next ones down if the registry does not know it (for suffixes such as `co.uk`). Redirects are not followed.
- Zone-file drift reads only the standard master-file format. octoDNS (YAML) and dnscontrol (JavaScript) sources would each need a parser dependency; both tools can write a zone file. The file is an input to the run, not an observation, and is not stored. DRF findings are not carried across runs the way deep findings are: a run without `--expect` resolves them.
- Certificate checks take their data from the same crt.sh answer as discovery. A run that did not read the logs carries CRT findings forward, as light runs do for deep findings. A list that was cut short or is longer than 2,000 certificates counts as no data, so a missing renewal cannot be inferred from half a list (raised by the automated security review). CRT-02 maps issuer names to CAA domains with a small built-in table and judges only certificates issued in the last 30 days.
- DKIM: selectors cannot be enumerated, so eight common names are tried and only a selector the user named is reported as missing. The RSA key size is read with a minimal DER reader, no ASN.1 dependency.
- TLSA records are checked for usable parameters and a signed zone only. Comparing them with the mail server's certificate would mean connecting to port 25, which zoneblick does not do.
- DNSSEC chain: the root trust anchors (key tags 20326 and 38696) are built in and were compared with the live root key set on 2026-11-13. A signature made by a key that is not in the signer's key set counts as broken, not as untried. Record-set signatures are checked in deep runs only, since they double the queries of a run. The query cap counts queries sent, not verdicts (raised by the automated security review).
- A wildcard-synthesised answer is verified under the wildcard owner name, taken from the label count in the signature.
- Takeover signatures: 21 more imported from nuclei-templates, 32 in all. Heroku, Netlify, Fastly, Shopify and Azure were asked for and left out: the upstream project has no body-text template for them, and inventing one would be guessing. One signature (Zendesk) is matched without regard to case, as upstream does.
- Providers: Cloudflare, Gandi, Hetzner and Route 53 added beside DigitalOcean. Route 53 needs AWS Signature Version 4, written with `ring` and `sha2` and tested against Amazon's published example; its XML answers are read with a small tag scanner. Hetzner is read through the Hetzner Cloud API, on the understanding that the DNS Console API is being retired; that has not been confirmed against the live service. None of the five has been run against its live API.
- Slack and Discord get the alert as a chat message. `&`, `<` and `>` are escaped for Slack, because record data comes from the DNS and could carry `<!channel>` (raised by the automated security review); Discord mentions are switched off in the request. Webhook addresses are kept out of error messages.
- Metrics are under `/api/v1/metrics` and need the token like the rest of the API: they name zones and say what is wrong with them.
- The digest's clock is kept in a new `meta` table (store layout version 5), so a restart does not send it again.
- Packaging: `.deb` and `.rpm` are built with `dpkg-deb` and `rpmbuild` from one staging tree, no packaging tool dependency. The release build installs the `.deb` on the runner and checks that the service answers, which is the first automated test of the systemd setup. The Homebrew formula lives in this repository (`brew tap` with the repository URL), and the release workflow commits the new formula to `main` as `github-actions[bot]`.
- The GitHub Action is a composite action that calls `install.sh`; it runs against the live DNS, so the release workflow tries it once after publishing and CI does not.
- Web UI: the page already asked for the API token; "login" came down to adding "Sign out". The timeline shows the latest 200 runs. `docs/demo.html` does not have the timeline.

## 0.12.1: red team / blue team review

- The review and its results are in the README under "Security review". Decisions taken while fixing:
- Run deadline: 15 minutes per zone by default (`[schedule] run_timeout`), enforced in the daemon. The CLI has no deadline; the caps on nameserver names (26) and addresses (8 per name) bound it, and a person can press Ctrl-C.
- A failed run alerts once, when failures start, through every sink. It is sent as critical: a zone that cannot be checked may be a hijacked one.
- Private address ranges are still queried over DNS, because internal zones are a real use. Loopback, link-local, multicast and unspecified addresses never are. Pages (MTA-STS policy, hosting-service page) are fetched from public addresses only, resolved by zoneblick and pinned for the connection.
- No-token mode stays the default on localhost, for a tool that must work with no setup. It refuses proxied requests. Requiring a token always, or a unix socket, was considered and left for later.
- The UI model is cached per "generation" (bumped when a run starts or ends and on a mute) combined with the newest run ID in the database.
- Not done: signed releases or build attestations, pinning the container base image by digest, verifying DNSSEC denials, rate-limiting token guesses. They are listed as open in the README.

## 0.12.2

- Three weaknesses in the 0.12.1 fixes, raised by the automated review of that commit. The address pin binds a host name, so a URL built from a record name that parses as another host or as an IP address is refused, and only names of letters, digits, hyphens, underscores and dots are fetched. "Not public" now covers IPv6 forms that embed IPv4 and more special-purpose IPv4 blocks. The name limit keeps the user's own names and cuts only discovered ones, in name order, with one alert when it is reached.
- The pin check uses `reqwest::Url` and a parse as `IpAddr`; no `url` dependency was added.

## 0.13.0

- Build provenance: GitHub artifact attestations for every release file and the image, not a project signing key, which would need key management. The install script verifies with `gh attestation verify`, pinned to the release workflow and the tag. Releases without an attestation are listed by exact tag in the script; an automatically chosen "newest" release that is on that list is refused. Without `gh` the script warns and goes on, since requiring a GitHub login for an install would lock most people out; `--require-attestation` makes it strict, and the Action uses that when it has a token.
- Built-in TLS was not added: it needs `tokio-rustls` as a direct dependency, and the question about adding it was dismissed. The daemon can listen on a unix socket instead (mode 0660, made inside a private directory and moved into place so it is never reachable with wider permissions).
- The mail-certificate check uses `rustls`, already a direct dependency, in blocking mode on a blocking thread, with a 30-second deadline for the whole exchange. The certificate is not validated against any authority: under DANE the TLSA record is the trust statement. Handshake signatures are still verified.
- Denial proofs: signatures on NSEC and NSEC3 records are verified. A signature whose label count is lower than the owner's is from a wildcard and does not count. A no-DS proof needs the NS bit and no SOA bit. NSEC3 opt-out is accepted only for a child directly below the parent zone, with a record at the parent's own hash. No proof at all is "unknown", not "bogus": zoneblick queries from where it runs, and a middlebox stripping records is not the zone's fault.
- New record types are asked by name shape, not for every name: HTTPS for ordinary names, SRV and SVCB for underscore names, PTR in reverse zones. That keeps a run at seven or eight queries per name and server.
- `zoneblick plan` reads only the types the comparison knows (A, AAAA, CNAME, MX, TXT, CAA, NS) but tracks every name and type in the file for the CNAME rules. Changes do not set its exit code.
- Vantage points are pull-based over the existing API: no agent, no new protocol. The comparison is with the other side's latest stored run, not a simultaneous one. Tokens go only to https addresses.
- Not done: live tests of the five DNS-host integrations. They need an account and a token at each host.

## 0.13.1: second audit, and HTTPS

- Built-in HTTPS, with `tokio-rustls` as a direct dependency, approved by the owner; it was already in the dependency tree. Handshakes run in their own tasks with a five-second limit, at most eight per client address, and are dropped, not queued, when all 256 slots are taken. Certificate files are read again when their modification time changes. No ACME, no HTTP-to-HTTPS redirect.
- The README keeps one record of all security audits, newest first, older ones in short form, with a single "Open now" list that is kept current.
- Signature verification is bounded per record set (16 attempts) and per answer (32 keys) rather than moved to a blocking thread: with the bound the cost is that of a normal answer.
- The no-token proxy problem is not solved, only narrowed (HTTP/1.0 refused). Making a token mandatory would solve it and would break every existing no-token install; that is the owner's decision and is listed as open.
- DANE usage 2 gives no verdict rather than a path validation, which would need a certificate-path library as a direct dependency.
- A DS record with a digest type that cannot be computed matches nothing. SEC-01 ignores such records, so a zone with only those gets no SEC-01 finding rather than a false one.
- The deep phase has half the run's time and is marked as tried before it starts.
- The socket's directory must not be writable by group or others and must have the same owner as a directory the daemon just made in it; there is no direct way to ask for the process's user without another dependency.

## 0.14.0: the API token is mandatory

- Decided by the owner after both audits flagged the no-token mode. The daemon does not refuse to start without a token in the config: it makes one on first start and keeps it in `api-token` in the data directory, mode 0600, so a fresh install still needs no setup beyond reading that file. `zoneblick token --show CONFIG` prints it.
- The made token is stored as it is, because the web UI's user has to be able to read it somewhere. A token set through `token_sha256` is still stored only as a hash.
- The Host check, the proxy-header refusal and the HTTP/1.0 refusal are removed: they existed only for the no-token mode. The cross-site check on requests that change something stays.
- A vantage point on this machine may be reached over plain http with a token; any other needs https.
- This breaks API clients that sent no token. It is in the README under "The API token".

## After 0.14.0: fixes from the review of the token change

- A `[[vantage]]` url is parsed with the HTTP client's own parser. "This machine" is decided from the parsed host, and a url with a user name or password is refused: `http://127.0.0.1:80@other.example/` used to pass as local.
- On Windows the token file and a new database are made inside a new directory already limited to the current user with `icacls` (inheritance removed, one grant, Everyone / Authenticated Users / Users removed), then moved into place: narrowing a file after making it would leave a moment in which another user could open it. No new dependency. For the token it fails closed: no token is written if the permissions cannot be set. For the database it is best effort. SQLite's side files are narrowed after the database is first opened; ones made on a later open take the directory's permissions again.
- The Docker starter config ships without `token_sha256`, so the daemon makes the token; the hash stays as a commented option.
