# zoneblick

A self-hosted DNS zone watchdog. zoneblick asks every authoritative nameserver for every record you care about, checks the answers, and keeps a history, so you know when your DNS drifts.

**Status:** Phase 1. `zoneblick check` checks a zone once. `zoneblick run` stores each run in a SQLite file and `zoneblick diff` shows what changed between runs. The daemon, alerts and web UI are not built yet. The current release, `v0.1.1`, is an early pre-release and has `check` only; `run` and `diff` are in the source and will be in the next release.

- Website: https://zoneblick.com
- Demo with sample data: https://zoneblick.com/demo.html
- Design document: [DESIGN.md](DESIGN.md)

## What it looks like

A check of a deliberately broken test zone. One nameserver refuses queries for the zone, and the other two serve different SOA serials:

![Terminal output of zoneblick check for a broken zone: one critical finding, DEL-02, for a lame nameserver, and one warning, CON-01, for mismatched SOA serials](screenshots/check-findings.png)

A healthy zone, checked live:

![Terminal output of zoneblick check for example.com: the delegation path from the root, twelve nameserver addresses all answering over UDP and TCP, and no findings](screenshots/check-clean.png)

What changed between two stored runs of a zone:

![Terminal output of zoneblick diff: a CNAME target modified on every nameserver, a TXT record removed, an A record changed on one nameserver only, an A record added, and a new consistency finding opened](screenshots/diff.png)

The web interface is planned, not built. The [demo](https://zoneblick.com/demo.html) shows the intended design with invented sample data:

![The planned zoneblick web interface, shown with sample data: a list of zones on the left and the findings for example.org on the right](screenshots/demo-ui.png)

## Platforms

zoneblick runs on Linux, macOS and Windows. The same tests run on all three in CI on every change.

| | Linux | macOS | Windows |
|---|---|---|---|
| Release binary | x86_64 and ARM 64-bit | Apple Silicon and Intel | 64-bit x86 (runs on ARM PCs through emulation) |
| Archive | `.tar.gz` | `.tar.gz` | `.zip` |
| Extra packages needed | None; the binary is statically linked, SQLite included | None | None |
| Signed | Not applicable | No; see the [macOS note](#macos-apple-could-not-verify-warning) | No |
| Install with | `curl`, `tar`, `sudo install` | `curl`, `tar`, `sudo install` | PowerShell |
| Build from source | Yes | Yes | Yes |
| Colour output | Yes | Yes | Yes, in Windows Terminal and PowerShell 7; the old console may show raw escape codes |

On every platform:

- Colour is used only when the output is a terminal. Set the `NO_COLOR` environment variable to turn it off.
- zoneblick sends its own DNS queries to port 53 over UDP and TCP, so outbound DNS must be allowed. It does not use the system resolver.
- IPv6 checks need working IPv6 on the machine. Without it, the IPv6 checks are skipped and the report says so.

## Install

There are two ways to install zoneblick: download a binary, or build it from source.

### Download a binary

Each release on the [releases page](https://github.com/cschweda/zoneblick/releases) has a ready-built binary for these systems. The current release is `v0.1.1`.

| System | File name ends in |
|---|---|
| Linux, x86_64 (most servers and VPSs) | `x86_64-unknown-linux-musl.tar.gz` |
| Linux, ARM 64-bit (Raspberry Pi, ARM servers) | `aarch64-unknown-linux-musl.tar.gz` |
| macOS, Apple Silicon | `aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `x86_64-apple-darwin.tar.gz` |
| Windows, 64-bit | `x86_64-pc-windows-msvc.zip` |

The Linux binaries are statically linked, so they run on any distribution with no other packages. The Windows binary also runs on ARM PCs through emulation.

Each set of commands below downloads the binary, installs it and runs a first check. Change `v0.1.1` to install another release.

**Linux**

```
V=v0.1.1
T=$(uname -m)-unknown-linux-musl

curl -LO https://github.com/cschweda/zoneblick/releases/download/$V/zoneblick-$V-$T.tar.gz
tar -xzf zoneblick-$V-$T.tar.gz
sudo install zoneblick-$V-$T/zoneblick /usr/local/bin/

zoneblick check example.org
```

**macOS**

```
V=v0.1.1
A=$(uname -m); [ "$A" = arm64 ] && A=aarch64
T=$A-apple-darwin

curl -LO https://github.com/cschweda/zoneblick/releases/download/$V/zoneblick-$V-$T.tar.gz
tar -xzf zoneblick-$V-$T.tar.gz
sudo mkdir -p /usr/local/bin
sudo install zoneblick-$V-$T/zoneblick /usr/local/bin/

zoneblick check example.org
```

**Windows (PowerShell)**

```
$V = "v0.1.1"
$T = "x86_64-pc-windows-msvc"

Invoke-WebRequest "https://github.com/cschweda/zoneblick/releases/download/$V/zoneblick-$V-$T.zip" -OutFile zoneblick.zip
Expand-Archive zoneblick.zip -DestinationPath .

& ".\zoneblick-$V-$T\zoneblick.exe" check example.org
```

On Windows the binary stays in the unpacked folder. To run `zoneblick` from any folder, move `zoneblick.exe` to a folder on your `PATH`. The Windows binary is not signed.

Each release also has a `SHA256SUMS` file. To check a download against it, on Linux:

```
curl -LO https://github.com/cschweda/zoneblick/releases/download/$V/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

On macOS the last line is `shasum -a 256 --check --ignore-missing SHA256SUMS`. On Windows, compare the output of `Get-FileHash zoneblick.zip` with the line for the zip in `SHA256SUMS`.

To update, repeat the steps with a newer release. To remove zoneblick, delete the binary (`/usr/local/bin/zoneblick`, or the unpacked folder on Windows).

#### macOS: "Apple could not verify" warning

The macOS binaries are not signed or notarised by Apple, because that needs a paid Apple developer account. If you download the archive with a web browser, macOS marks it as quarantined and refuses to run the binary, with a message such as *"zoneblick" cannot be opened because Apple cannot verify that it is free of malware*.

Either of these avoids it:

- Download with `curl`, as in the commands above. Files fetched with `curl` are not quarantined.
- Or remove the quarantine mark from a browser download after unpacking it:

  ```
  xattr -d com.apple.quarantine zoneblick-*/zoneblick
  ```

Check the download against `SHA256SUMS` first, since that is the only verification an unsigned binary has. Building from source avoids the question altogether.

### Build from source

You need a stable [Rust toolchain](https://rustup.rs), version 1.88 or later, and a C compiler, because SQLite is compiled in (`gcc` or `clang` on Linux, the Xcode command line tools on macOS, the Visual Studio build tools on Windows).

```
cargo install --git https://github.com/cschweda/zoneblick
```

This builds the latest source and puts the `zoneblick` binary in `~/.cargo/bin`, which rustup adds to your `PATH`. Check it with `zoneblick --version`. The same command works on Linux, macOS and Windows.

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

zoneblick is one binary with no config file and no data directory in this phase, so removing it leaves nothing behind however you installed it. It is not on crates.io, and there is no install script or Docker image yet; those come with the packaging phase in the [design](DESIGN.md).

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

## Track changes over time

`run` and `diff` are newer than the `v0.1.1` binaries. Until the next release, [build from source](#build-from-source) to use them.

`run` does everything `check` does, then asks every nameserver for the records of the names you care about, and stores the result in a SQLite file:

```
zoneblick run example.org --name www --name api --name mail
```

- **Names** are given once. They are remembered in the database, so later runs are just `zoneblick run example.org`. Use `--forget-name` to stop checking one. The zone apex is always checked.
- **Record types** asked for each name: A, AAAA, CNAME, MX, TXT and CAA, plus SOA and NS at the apex.
- **The database** is `zoneblick.sqlite` in the current directory unless you pass `--db FILE`. It is created on the first run. It holds the names in your zones and any problems found, so keep it private.

Each run after the first ends with what changed since the previous one. `diff` shows the same comparison for any two stored runs:

```
zoneblick diff example.org
zoneblick diff example.org --from 12 --to 40
zoneblick diff example.org --ignore "_acme-challenge.*"
zoneblick zones list
```

```
zoneblick diff drift.example.
run #1 (2023-11-14 22:13 UTC) -> run #2 (2023-11-14 23:13 UTC)

  MODIFIED  api.drift.example. CNAME
    - app.hosting.example.
    + new-app.hosting.example.
    on every nameserver
  REMOVED   drift.example. TXT
    - "v=spf1 mx -all"
    on every nameserver
  MODIFIED  shop.drift.example. A
    + 192.0.2.99
    ns1.drift.example. (198.51.100.1): 192.0.2.20 -> 192.0.2.99
  ADDED     staging.drift.example. A
    + 192.0.2.50
    on every nameserver
  SOA serial 2026111301 -> 2026111302
  OPENED    CON-02 warning  Nameservers serve 2 different versions of the A record set for shop.drift.example.

Changes: 1 added, 1 removed, 2 modified, 0 TTL; findings: 1 opened, 0 resolved
```

You can reproduce that output offline from a checkout, using two recorded states of a test zone:

```
zoneblick run drift.example --db demo.sqlite --name www --name api --name shop --name staging --replay tests/fixtures/drift.example.before.json
zoneblick run drift.example --db demo.sqlite --replay tests/fixtures/drift.example.after.json
zoneblick diff drift.example --db demo.sqlite
```

### What counts as a change

A change is a difference in what the nameservers, taken together, serve for a name and type. To keep noise down:

- **Rotation is not drift.** If servers hand out different parts of the same pool of records from run to run, nothing is reported.
- **A change on one server is named.** When only some servers changed, the diff lists them with their before and after values. When all did, it says "on every nameserver".
- **TTL changes are reported separately**, as `TTL`, and do not count as a change to the records.
- **The SOA serial** is shown on one line when it moves and is not counted as a change by itself.
- **`--ignore PATTERN`** leaves out names that match; `*` matches anything.
- **Only authoritative answers count.** A server that did not answer in one of the runs is left out of the comparison for that run.

Findings have a lifecycle too: a finding seen in a run is open, and one that is no longer seen is resolved. The diff lists findings that opened or resolved between the two runs.

Learning which names are volatile, and comparing against a pinned baseline, are designed but not built yet.

## Command reference

| Command | What it does | Stores anything |
|---|---|---|
| `zoneblick check <zone>` | Checks the zone once | No |
| `zoneblick run <zone>` | Checks the zone and its names, stores the run, shows changes since the last run | Yes |
| `zoneblick diff <zone>` | Compares two stored runs | No |
| `zoneblick zones list` | Lists the stored zones | No |

### Options

| Option | Commands | Effect |
|---|---|---|
| `--json` | all | Print one JSON document instead of text |
| `--db FILE` | `run`, `diff`, `zones list` | The database file. Default: `zoneblick.sqlite` |
| `--name NAME` | `run` | Also check this name in the zone; repeatable; remembered |
| `--forget-name NAME` | `run` | Stop checking a remembered name; repeatable |
| `--from RUN`, `--to RUN` | `diff` | The runs to compare. Default: the latest and the one before it |
| `--ignore PATTERN` | `diff` | Leave out matching names; repeatable |
| `--record FILE` | `check`, `run` | Save every DNS exchange of the run to a fixture file |
| `--replay FILE` | `check`, `run` | Answer from a fixture file instead of the network |

### Exit codes

For `check` and `run`:

| Code | Meaning |
|---|---|
| `0` | Clean (`info` findings do not count) |
| `1` | Notices or warnings only |
| `2` | At least one critical finding |
| `3` | The run itself failed: bad arguments, zone not found, not a zone apex, no nameserver reachable |

For `diff`: `0` nothing changed, `1` something changed, `3` the command failed (no database, unknown zone or run, fewer than two runs). A moved SOA serial alone is not a change. `zones list` exits `0`, or `3` on failure.

### Checks

| ID | Check | Severity |
|---|---|---|
| DEL-01 | Parent NS set differs from child NS set | warning |
| DEL-02 | Lame delegation: listed NS is not authoritative, does not answer, or has no address | critical |
| DEL-03 | Glue at parent differs from the address the NS name resolves to | warning |
| DEL-04 | Fewer than two nameservers, or all in one /24 or /48 | notice |
| DEL-05 | NS target is a CNAME | warning |
| CON-01 | SOA serial differs across authoritative servers | warning |
| CON-02 | A record set differs across servers: the apex NS set and SOA fields other than the serial, and with `run`, every name and type it collects | warning |
| CON-03 | Server answers over UDP but not over TCP | warning |
| CON-04 | Server does not answer on a published IPv6 address | notice |
| CON-05 | Server mishandles EDNS or truncation | notice |

DEL-06 (nameserver's domain unregistered or expired) needs registry data and is a stub. If IPv6 does not work on your machine, CON-04 is skipped and one `info` finding says so.

### Politeness

At most 16 queries are in flight at once and no server address gets more than 5 queries per second. UDP queries time out after 3 seconds and TCP after 5; a timed-out query is retried twice, after 0.5 and 1 second. A check sends five queries to each nameserver address. A stored run adds six queries per name to each address that answered.

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
| `records` | Only from `run`: one entry per name, type and server, with `name`, `qtype`, `ns_name`, `address`, `transport` and `outcome` |
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

A record `outcome` has a `kind`: `answer` (with `rcode`, `authoritative`, `ttl` and `rdata`, a sorted list of record data in text form), `timeout`, `net_error` or `malformed`.

### `run --json`

| Field | Contents |
|---|---|
| `schema_version` | `1` |
| `run` | `id`, `db`, `names` (checked besides the apex), `queries` |
| `report` | The document described above, with `records` |
| `diff` | The diff against the previous stored run, or `null` for the first run |

### `diff --json`

| Field | Contents |
|---|---|
| `schema_version` | `1` |
| `zone` | The zone |
| `from`, `to` | The two runs: `id`, `started_at_unix` |
| `changes` | One per changed record set: `name`, `rtype`, `kind` (`added`, `removed`, `modified`, `ttl`), `added`, `removed`, `ttl_before`, `ttl_after`, `servers` (each with `ns_name`, `address`, `before`, `after`), `all_servers` |
| `soa_serial` | `before` and `after` when the serial moved, otherwise `null` |
| `delegation` | `ns_added`, `ns_removed`, `glue_added`, `glue_removed` when the parent's delegation changed, otherwise `null` |
| `findings_opened`, `findings_resolved` | Each with `severity`, `check_id`, `name`, `summary`, `fingerprint` |
| `not_compared` | Record sets left out: `name`, `rtype`, `reason` (`ignored`, `not_in_older_run`, `not_in_newer_run`) |
| `summary` | Counts: `added`, `removed`, `modified`, `ttl`, `findings_opened`, `findings_resolved` |
| `changed` | `true` when anything other than the SOA serial changed |

A full example is in [`tests/fixtures/drift.example.diff.json`](tests/fixtures/drift.example.diff.json), also pinned by a test.

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

`error.kind` is one of `invalid_name`, `no_network`, `zone_not_found`, `not_a_zone`, `servers_failed`, `too_many_referrals`, `no_server_reachable`, `name_outside_zone`, `no_database`, `unknown_zone`, `unknown_run`, `not_enough_runs`, `store_error`, `fixture_error`.

## Development

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                 # offline
cargo test -- --ignored    # the one test that uses the live network
```

Tests never use the network. Checks are tested against hand-built observations, and the resolver against recorded DNS exchanges in `tests/fixtures/`, replayed through the same code path as a live run. The `broken.example`, `good.example` and `drift.example` fixtures are generated from `tests/common/mod.rs`; `example.com.json` is a recording of a real run. After an intended change, regenerate the generated files with `ZONEBLICK_REGEN=1 cargo test`.

The same lint and tests run in CI on Linux, macOS and Windows for every push and pull request (`.github/workflows/ci.yml`).

### Releasing

Binaries are built by GitHub Actions (`.github/workflows/release.yml`). To publish a release, set the version in `Cargo.toml`, commit, then push a matching tag:

```
git tag v0.2.0
git push origin v0.2.0
```

The workflow checks that the tag matches the crate version, runs the lint and tests, builds static Linux binaries (x86_64 and aarch64), macOS binaries (Apple Silicon and Intel) and a Windows binary, and attaches them to a GitHub Release with a `SHA256SUMS` file. Each archive holds the binary, this README and both license files. The macOS and Windows binaries are not signed. Versions below 1.0 are marked as pre-releases. A pull request that changes the workflow or the Cargo files runs the same builds without publishing.

## What it will do

- **Zone health:** delegation, nameserver consistency, DNSSEC.
- **Exposure:** dangling records and subdomain-takeover risk.
- **Drift history:** every run stored and compared with the last. The store and the diff exist now; scheduled runs and alerts do not.

One binary, one config file, one SQLite file, on your own server.

## Repository layout

| Path | Contents |
|---|---|
| `DESIGN.md` | High-level design |
| `DECISIONS.md` | Decisions made during implementation, one line each |
| `LICENSE-MIT`, `LICENSE-APACHE` | The two licenses |
| `.github/workflows/release.yml` | Builds and publishes release binaries |
| `KICKOFF.md` | Claude Code prompt for Phase 0 |
| `src/observe.rs` | The recorded observations of a run (plain data) |
| `src/resolver/` | Iterative resolver, per-server probing, transport, record and replay |
| `src/checks/` | The checks: pure functions over observations, no I/O |
| `src/output/` | Terminal and JSON rendering |
| `src/store.rs` | The SQLite store: snapshots, record sets, finding lifecycle |
| `src/diff.rs` | The diff engine: pure functions over two stored runs |
| `src/cli.rs` | The commands |
| `tests/` | Offline tests and DNS fixtures |
| `screenshots/` | The images in this README |
| `.github/workflows/ci.yml` | Lint and tests on Linux, macOS and Windows |
| `docs/` | The project website, served by GitHub Pages |

## Responsible use

Scan only zones you control.

## License

zoneblick is licensed under either of these, at your option:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

This is the usual dual license for Rust projects. You may use, change and redistribute zoneblick under whichever of the two suits you.

Unless you state otherwise, any contribution you intentionally submit for inclusion in zoneblick, as defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or conditions.
