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
