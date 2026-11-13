# zoneblick — Claude Code kickoff prompt (Phase 0)

Paste everything below the line into Claude Code, started in the root of this repository.

---

You are starting the implementation of **zoneblick**, a self-hosted DNS zone watchdog written in Rust. The full design is in `DESIGN.md` in this repository. Read it completely before doing anything else. It is the source of truth; where this prompt and the design doc disagree, stop and ask me.

## Scope of this session: Phase 0 only

Build the one-shot command:

```
zoneblick check <zone> [--json]
```

It resolves the zone from the root, queries every authoritative nameserver directly, runs the delegation and consistency checks, prints the findings, and exits. No config file, no database, no daemon, no web UI. Those are later phases. Do not build toward them beyond keeping the module boundaries in the design doc.

### In scope

1. **Iterative resolver.** Start from built-in root hints. Follow referrals down to the zone. Record the whole delegation path: every referral, the NS set at each level, and glue. Do not use the system resolver or any recursive resolver for zone data.
2. **Per-server queries.** For the zone apex, query each authoritative nameserver separately for SOA and NS, over UDP and TCP, over IPv4 and IPv6. Keep each server's answer separate; never merge them before the checks see them.
3. **Checks.** Implement as pure functions over the recorded observations, with no network access inside a check:
   - `DEL-01` to `DEL-05` (delegation)
   - `CON-01` to `CON-05` (consistency)
   - `DEL-06` needs registry data; leave a stub and a note, do not implement it.
4. **Output.** Human-readable terminal output by default, grouped by severity, each finding showing its check ID, the name, and the evidence. `--json` prints one stable JSON document instead.
5. **Exit codes.** `0` clean, `1` notices or warnings only, `2` at least one critical, `3` the run itself failed (zone not found, no nameserver reachable).
6. **Politeness.** Bounded concurrency, a per-server query rate cap, timeouts and limited retries with backoff. Defaults come from the design doc.

### Out of scope for this session

SQLite, snapshots, diffing, the scheduler, alerts, the HTTP API, the web UI, DNSSEC checks, mail and policy checks, takeover checks, the deep checks, discovery (CT logs, AXFR, provider APIs), packaging.

## Technical constraints

- **Rust, stable toolchain, edition 2021 or later.** Async with `tokio`.
- **DNS wire format:** `hickory-proto` for message parsing and serialisation only. The iteration logic is ours, because we need the intermediate answers a normal resolver hides. Check the crate's current documentation before relying on any API from memory.
- **CLI:** `clap` with derive.
- **JSON:** `serde` and `serde_json`.
- **Errors:** `thiserror` in library code, `anyhow` only at the binary edge.
- Ask me before adding any dependency not listed here.
- One Cargo package for now, with modules that match the design doc's components: `resolver`, `observe` (the recorded observations), `checks`, `output`, `cli`. Keep `checks` free of any I/O so it can be tested offline.
- Do not touch anything under `docs/`. That is the live project website.

## Testing

- Unit tests must not use the network. Test checks against hand-built observations and against recorded DNS exchanges stored as fixtures in `tests/fixtures/`.
- Add a small record-and-replay layer so a real run can be captured to a fixture and replayed deterministically.
- Put any test that needs the live network behind `#[ignore]` so `cargo test` stays offline.
- `cargo fmt --check`, `cargo clippy -- -D warnings` and `cargo test` must all pass before you call anything done.

## How to work

1. Read `DESIGN.md`. Then give me a short implementation plan for Phase 0: the module layout, the core data types for observations and findings, and the order you will build things in. Wait for my go-ahead before writing code.
2. Build in small steps, in this order unless your plan argues for another: observation types, resolver, per-server querying, checks, output, CLI wiring.
3. Commit after each working step with a clear message. Do not push; I will push.
4. When something in the design doc is ambiguous or looks wrong, ask rather than guess. Note any decision you had to make in a `DECISIONS.md` file, one line each.
5. Only run the tool against `example.com`, `example.org`, the reserved test zones you find documented by DNS operators for testing, or a zone I name. Do not scan arbitrary third-party domains.

## Definition of done for Phase 0

- `zoneblick check <zone>` prints the delegation path summary and all DEL and CON findings for a real zone.
- `--json` output is stable and documented in the README.
- A deliberately inconsistent fixture (mismatched SOA serials, one lame nameserver) produces the expected findings in tests.
- Formatting, clippy and tests pass.
- The README has a short "Try it" section for the `check` command.

Start by reading `DESIGN.md` and giving me the plan.
