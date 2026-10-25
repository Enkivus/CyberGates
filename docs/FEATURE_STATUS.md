# Feature Status

Last updated: 2026-10-25 · v0.1.0

Status is based on code presence **and verification**, not screen existence.
✅ implemented · 🟡 partial · ⬜ not started · ⛔ unavailable by design

## 1. Overview / posture

- ✅ Explainable weighted score with per-check evidence and exclusions
- ✅ macOS native posture checks (firewall, FileVault, SIP, Gatekeeper, OS support,
  screen lock, update schedule, SSH/screen sharing, guest, backup metadata, XProtect)
- ✅ Recommended actions ordered by severity with evidence, fix, verification
- ✅ First-run audit, re-run, interrupted-audit recovery
- ✅ Device snapshot and coverage disclosure
- 🟡 Windows/Linux adapters (explicitly unavailable, no score)

## 2. Threat Protection

- 🟡 XProtect presence check only
- ⬜ Malware engine integration, real-time protection, quarantine, schedule
- ⛔ No fake "protected" state; no engine exists

## 3. Security Scanner

- ⬜ File/directory scans, progress, cancellation, scan history
- ✅ Posture audit exists in Overview, but it is **not** a malware scan

## 4. Vulnerabilities

- 🟡 Installed-software inventory on macOS: applications via `system_profiler`,
  Homebrew formulae via `brew list --versions`, searchable with signature/trust data
- 🟡 Optional Homebrew advisory matching: downloads Homebrew's OSV-format advisory
  database (~14 MB), indexes it in SQLite, records fetch time/counts, and matches only
  same-version revision patches (version-bump boundaries are reported as unverified)
- ⛔ Applications, other package managers, exploitability, and remediation are not matched
- ⛔ No loose name-only vulnerability claims; inventory alone is not a scan result

## 5. Network Security

- ✅ Read-only TCP/UDP socket inventory with process/PID where exposed
- ✅ Filters, counts, explicit scope warning
- ⬜ Discovery, authorized scanning, DNS/reputation checks, interface detail
- ⛔ No interception or external scanning

## 6. Firewall

- 🟡 Read-only macOS Application Firewall snapshot: global state, stealth, block-all,
  signed-software handling, and per-application allow/block exceptions
- ✅ Search/filter and explicit read-only/interpretation warnings
- ⬜ Rule changes, impact preview, apply/revert, verification
- ⛔ Never disables/flushes or edits firewall rules automatically

## 7. System Monitoring

- ✅ Live process snapshot, search, detail dialog
- ⬜ Security event monitoring, startup items, services, behavior detection
- ⛔ No process termination yet

## 8. Privacy

- 🟡 FileVault, screen lock, guest account, Gatekeeper signals via audit
- ⬜ App permissions, browser extensions, camera/mic/accessibility inventory
- ⛔ No universal tracking-prevention claim

## 9. Account Security

- ⬜ All integrations and guidance
- ⛔ Never collects passwords or authentication codes; no fabricated breaches

## 10. Incident Response

- ⬜ Incident creation, evidence timeline, response actions, verification, export
- ⛔ No destructive actions without a designed confirmation/audit workflow

## 11. Backup and Recovery

- 🟡 Time Machine destination + best-effort latest snapshot (bounded, may be unverified)
- ⬜ Restore verification, recovery instructions, history
- ⛔ Never modifies backups

## 12. Security Toolkit

- ⬜ Hashing, signatures/certs, DNS/IP/TLS diagnostics, metadata, log viewer, decoders
- ⛔ No exploit, credential-theft, stealth, or destructive tools

## 13. Device Management

- ⛔ No backend, accounts, or cloud sync. Local app is fully independent.

## 14. Reports and History

- ✅ Audit history, findings viewer, activity log
- ✅ Sanitized JSON and HTML export with sensitive-data warning
- 🟡 Scan/incident report types and OS notifications are not implemented

## 15. Settings

- ✅ Theme, retention (with pruning), notification preference, storage locations
- ✅ Telemetry and AI are visibly disabled; update attempts are rejected
- ⬜ Per-module configuration, log level, scheduled tasks

## Engineering quality

- ✅ Shared render error boundary, dismissible toast notifications, and accessible
  confirmation dialog; retention reductions are confirmed before pruning can occur
- ✅ Rust unit tests for scoring, DB, validation, lsof parsing
- ✅ Frontend unit tests for formatting utilities
- ✅ `cargo fmt`, `cargo clippy -D warnings`, `cargo test`
- ✅ `npm run typecheck`, `npm run lint`, `npm test`, `npm run build`
- ✅ Debug `.app` + `.dmg` built and launched on macOS; real audit persisted
- 🟡 CI matrix added but not yet observed running on all three OSes
- ⬜ Release-signed installers, auto-update, dependency audit in CI

## Next implementation priorities

1. Expand advisory coverage beyond Homebrew revision patches with a feed that provides
   reliable affected-version ranges; never guess applicability from generation-time
   boundaries.
2. Malware engine integration behind a trait + quarantine with safety controls.
3. Security event monitoring and a searchable timeline.
4. Windows and Linux audit adapters, tested on each platform.
5. Firewall rule read/apply/revert with impact preview and audit trail.
6. Incident workflow built on real events; then toolkit and AI.
