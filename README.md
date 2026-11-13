# zoneblick

A self-hosted DNS zone watchdog. zoneblick asks every authoritative nameserver for every record you care about, checks the answers, and keeps a history, so you know when your DNS drifts.

**Status:** in design. Nothing is released yet.

- Website: https://zoneblick.com
- Demo with sample data: https://zoneblick.com/demo.html
- Design document: [DESIGN.md](DESIGN.md)

## What it will do

- **Zone health:** delegation, nameserver consistency, DNSSEC.
- **Exposure:** dangling records and subdomain-takeover risk.
- **Drift history:** every run stored and compared with the last.

One binary, one config file, one SQLite file, on your own server.

## Repository layout

| Path | Contents |
|---|---|
| `DESIGN.md` | High-level design |
| `KICKOFF.md` | Claude Code prompt for Phase 0 |
| `docs/` | The project website, served by GitHub Pages |

## Responsible use

Scan only zones you control.

## License

Not chosen yet.
