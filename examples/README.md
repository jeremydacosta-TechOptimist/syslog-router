# Lab fixtures

Every file in this directory is deterministic lab data: hostnames use the reserved
`.example` domain and every IPv4 address comes from an RFC 5737 documentation range
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Nothing here is real traffic.

## `lab-logs/mixed.log`

30 syslog lines covering the formats the parser understands:

| Lines | Format | Notes |
| --- | --- | --- |
| 1-10 | RFC 5424 | structured data, nil values, `Z` timestamps |
| 11-20 | RFC 3164 | `Mmm dd hh:mm:ss` timestamps, tags with and without `[pid]` |
| 21-26 | Cisco-style | `%FACILITY-SEVERITY-MNEMONIC:` tokens, with and without a clock prefix |
| 27 | lenient fallback | line without a `<PRI>` header |
| 28-30 | RFC 3164 | emergency, alert and debug severities |

The log exercises the demo rules: four SSH authentication failures, four firewall
denials, three cron jobs, two emergency/alert events and four chatty `DEBUG` lines
that the example rule set drops. All timestamps are fixed (2026-03-01); the commands in
the top-level README pass `--now 2026-03-02T00:00:00Z` so that RFC 3164 year inference
and timestamp-less lines are reproducible.

## `lab-rules.json`

Five ordered rules used by the README walkthrough:

1. `auth-failures` - counts messages from `sshd` that contain `Failed password`.
2. `firewall-denies` - matches `fw-*.example` hosts and copies blocked/denied messages
   to `out/denied-events.log` (relative to the working directory).
3. `critical-alerts` - counts emergencies and alerts (`severity_max: 1`).
4. `cron-jobs` - counts messages whose application is `CRON`.
5. `drop-debug-noise` - drops `DEBUG` lines from the `app` application and stops rule
   evaluation for them.

Validate the file at any time with:

```console
syslogrouter rules validate examples/lab-rules.json
```
