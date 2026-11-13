# zoneblick

A self-hosted DNS zone watchdog. zoneblick asks every authoritative nameserver for every record you care about, checks the answers, and keeps a history, so you know when your DNS drifts.

**Status:** Phase 0. The one-shot `zoneblick check` command works; the daemon, history and web UI are not built yet. Nothing is released.

- Website: https://zoneblick.com
- Demo with sample data: https://zoneblick.com/demo.html
- Design document: [DESIGN.md](DESIGN.md)

## Install

There are no release binaries yet, so you build zoneblick from source. You need a stable [Rust toolchain](https://rustup.rs), version 1.88 or later.

```
cargo install --git https://github.com/cschweda/zoneblick
```

This builds the latest source and puts the `zoneblick` binary in `~/.cargo/bin`, which rustup adds to your `PATH`. Check it with `zoneblick --version`.

To install from a local checkout instead:

```
git clone https://github.com/cschweda/zoneblick
cd zoneblick
cargo install --path .
```

| To | Run |
|---|---|
| Update | The install command again, with `--force` |
| Install somewhere else | Add `--root /usr/local` (the binary goes in `/usr/local/bin`) |
| Remove | `cargo uninstall zoneblick` |

zoneblick is one binary with no config file and no data directory in this phase, so removing it leaves nothing behind. It is not on crates.io, and there is no install script or Docker image yet; those come with the packaging phase in the [design](DESIGN.md).

## Try it

Once installed:

```
zoneblick check example.com
```

Or, without installing, run it from a checkout with `cargo run -- check example.com`.

`check` resolves the zone from the root servers, asks every authoritative nameserver directly over UDP and TCP, IPv4 and IPv6, and reports what is wrong. It needs no config file and no database, and it never uses your system resolver for zone data.

```
zoneblick check example.com.

Delegation path
  . -> com.             asked a.root-servers.net. (198.41.0.4): 13 NS, 26 glue
  com. -> example.com.  asked a.gtld-servers.net. (192.5.6.30): 2 NS, 12 glue

Nameservers
  elliott.ns.cloudflare.com.  listed by: parent and zone
    108.162.195.228          serial 2418004112   udp: ok   tcp: ok
    ...

Findings
  None. All delegation and consistency checks passed.

Summary: 0 critical, 0 warning, 0 notice, 0 info
```

To see findings without touching the network, replay the deliberately broken test zone from a checkout of this repository:

```
zoneblick check broken.example --replay tests/fixtures/broken.example.json
```

### Options

| Option | Effect |
|---|---|
| `--json` | Print one JSON document instead of text |
| `--record FILE` | Save every DNS exchange of the run to a fixture file |
| `--replay FILE` | Answer from a fixture file instead of the network |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean (`info` findings do not count) |
| `1` | Notices or warnings only |
| `2` | At least one critical finding |
| `3` | The run itself failed: bad arguments, zone not found, not a zone apex, no nameserver reachable |

### Checks in Phase 0

| ID | Check | Severity |
|---|---|---|
| DEL-01 | Parent NS set differs from child NS set | warning |
| DEL-02 | Lame delegation: listed NS is not authoritative, does not answer, or has no address | critical |
| DEL-03 | Glue at parent differs from the address the NS name resolves to | warning |
| DEL-04 | Fewer than two nameservers, or all in one /24 or /48 | notice |
| DEL-05 | NS target is a CNAME | warning |
| CON-01 | SOA serial differs across authoritative servers | warning |
| CON-02 | Apex NS set, or SOA fields other than the serial, differ across servers | warning |
| CON-03 | Server answers over UDP but not over TCP | warning |
| CON-04 | Server does not answer on a published IPv6 address | notice |
| CON-05 | Server mishandles EDNS or truncation | notice |

DEL-06 (nameserver's domain unregistered or expired) needs registry data and is a stub. If IPv6 does not work on your machine, CON-04 is skipped and one `info` finding says so.

### Politeness

At most 16 queries are in flight at once and no server address gets more than 5 queries per second. UDP queries time out after 3 seconds and TCP after 5; a timed-out query is retried twice, after 0.5 and 1 second. A check sends five queries to each nameserver address.

## JSON output

`--json` prints one document. `schema_version` changes only when a field is removed, renamed or changes meaning; new fields may be added without a change. Field order is fixed, and findings and probes are sorted, so the same observations always give the same bytes. Names are lowercase and fully qualified, with a trailing dot.

| Field | Contents |
|---|---|
| `schema_version` | `1` |
| `zone` | The zone checked |
| `started_at_unix` | Start of the run, in seconds since the Unix epoch. The only time-dependent field |
| `vantage` | `ipv4`, `ipv6`: whether each address family works from this machine |
| `delegation_path` | Referrals from the root down. Each has `from_zone`, `to_zone`, `server_name`, `server_address`, `ns` and `glue` (`name`, `address`) |
| `nameservers` | One per NS hostname: `name`, `in_parent`, `in_child`, `glue`, `resolved`, `cname`, `resolve_error` |
| `probes` | Every query to every nameserver address: `ns_name`, `address`, `qtype`, `transport`, `edns`, `outcome` |
| `findings` | See below |
| `summary` | Counts: `critical`, `warning`, `notice`, `info` |
| `exit_code` | The process exit code |

A probe `outcome` has a `kind`: `response` (with `rcode`, `authoritative`, `truncated`, `opt_present`, `size`, `soa`, `ns`), `timeout`, `net_error` (with `message`) or `malformed` (with `message`).

Each finding has `check_id`, `severity`, `name`, `summary` (one line for people) and `evidence`. Evidence has a `kind` that fixes its other fields:

| Check | Evidence `kind` | Fields |
|---|---|---|
| DEL-01 | `ns_set_mismatch` | `parent`, `child`, `only_in_parent`, `only_in_child` |
| DEL-02 | `lame_server` | `ns_name`, `address`, `reason` (`not_authoritative`, `no_response`, `unresolvable`), `probes` |
| DEL-03 | `glue_mismatch` | `ns_name`, `glue`, `resolved` |
| DEL-04 | `too_few_nameservers` | `nameservers` |
| DEL-04 | `single_network` | `prefix`, `addresses` |
| DEL-05 | `ns_is_cname` | `ns_name`, `target` |
| CON-01 | `serial_mismatch` | `serials`: list of `value` and `servers` |
| CON-02 | `rrset_mismatch` | `rrtype`, `variants`: list of `value` and `servers` |
| CON-03 | `no_tcp` | `ns_name`, `address`, `probes` |
| CON-04 | `ipv6_unreachable` | `ns_name`, `address`, `probes` |
| CON-04 | `ipv6_not_tested` | `addresses` |
| CON-05 | `edns_problem` | `ns_name`, `address`, `problems` |

A full example is in [`tests/fixtures/broken.example.report.json`](tests/fixtures/broken.example.report.json); a test pins it byte for byte.

When the run fails, the document is shorter:

```json
{
  "schema_version": 1,
  "zone": "nothing.invalid.",
  "error": {
    "kind": "zone_not_found",
    "message": "zone nothing.invalid. does not exist (NXDOMAIN)"
  },
  "exit_code": 3
}
```

`error.kind` is one of `invalid_name`, `no_network`, `zone_not_found`, `not_a_zone`, `servers_failed`, `too_many_referrals`, `no_server_reachable`, `fixture_error`.

## Development

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                 # offline
cargo test -- --ignored    # the one test that uses the live network
```

Tests never use the network. Checks are tested against hand-built observations, and the resolver against recorded DNS exchanges in `tests/fixtures/`, replayed through the same code path as a live run. The `broken.example` and `good.example` fixtures are generated from `tests/common/mod.rs`; `example.com.json` is a recording of a real run. After an intended change, regenerate the generated files with `ZONEBLICK_REGEN=1 cargo test`.

## What it will do

- **Zone health:** delegation, nameserver consistency, DNSSEC.
- **Exposure:** dangling records and subdomain-takeover risk.
- **Drift history:** every run stored and compared with the last.

One binary, one config file, one SQLite file, on your own server.

## Repository layout

| Path | Contents |
|---|---|
| `DESIGN.md` | High-level design |
| `DECISIONS.md` | Decisions made during implementation, one line each |
| `KICKOFF.md` | Claude Code prompt for Phase 0 |
| `src/observe.rs` | The recorded observations of a run (plain data) |
| `src/resolver/` | Iterative resolver, per-server probing, transport, record and replay |
| `src/checks/` | The checks: pure functions over observations, no I/O |
| `src/output/` | Terminal and JSON rendering |
| `src/cli.rs` | The `check` command |
| `tests/` | Offline tests and DNS fixtures |
| `docs/` | The project website, served by GitHub Pages |

## Responsible use

Scan only zones you control.

## License

Not chosen yet.
