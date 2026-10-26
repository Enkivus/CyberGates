# Feature Status

Last updated: 2026-10-26 · v0.1.0

Status is based on code presence **and verification**, not screen existence.
✅ implemented · 🟡 partial · ⬜ not started · ⛔ unavailable by design

## 1. Overview / posture

- ✅ Explainable weighted score with per-check evidence and exclusions
- ✅ macOS native posture checks (firewall, FileVault, SIP, Gatekeeper, OS support,
  screen lock, update schedule, SSH/screen sharing, guest, backup metadata, XProtect)
- ✅ Recommended actions ordered by severity with evidence, fix, verification
- ✅ First-run audit, re-run, interrupted-audit recovery
- ✅ Device snapshot and coverage disclosure
- 🟡 Linux read-only network, startup, and current-user service inventories are available;
  verified Linux posture checks are still unavailable and no score is produced
- ⛔ Windows has no native adapter and no score

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
- 🟡 Linux package name/version inventory through [dpkg-query](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html),
  [RPM query formats](https://rpm.org/docs/latest/man/rpm-queryformat.7), or
  [pacman -Q](https://man.archlinux.org/man/core/pacman/pacman.8.en) where available;
  package integrity and vulnerability matching are not implemented
- 🟡 Optional Homebrew advisory matching: downloads Homebrew's OSV-format advisory
  database (~14 MB), indexes it in SQLite, records fetch time/counts, and only matches
  non-generated, same-version revision patches. Automatically generated boundaries are
  treated as unverified because Homebrew describes them as approximate.
- ⛔ Applications, other package managers, exploitability, and remediation are not matched
- ⛔ No loose name-only vulnerability claims; inventory alone is not a scan result

## 5. Network Security

- ✅ Read-only TCP/UDP socket inventory with process/PID where exposed
- ✅ macOS interface addresses and configured DNS resolver inventory (no DNS trust or
  reputation verdicts)
- 🟡 Linux interface addresses and configured `/etc/resolv.conf` nameserver entries;
  systemd stub resolvers may hide upstream DNS servers
- ✅ User-triggered DNS lookup and TLS certificate/handshake diagnostics in the toolkit;
  no HTTP request or reputation verdict
- ✅ Filters, counts, explicit scope warning
- ⬜ Discovery, authorized scanning, DNS trust/reputation checks, detailed interface diagnostics
- ⛔ No interception or external scanning

## 6. Firewall

- 🟡 Read-only macOS Application Firewall snapshot: global state, stealth, block-all,
  signed-software handling, and per-application allow/block exceptions
- ✅ Search/filter and explicit read-only/interpretation warnings
- ⬜ Rule changes, impact preview, apply/revert, verification
- ⛔ Never disables/flushes or edits firewall rules automatically

## 7. System Monitoring

- ✅ Live process snapshot, search, detail dialog
- 🟡 macOS launchd file inventory for standard user/system property-list directories;
  lists file names, paths, scope, and modification time only
- 🟡 macOS current-user launchd job list with running PID and last exit status;
  system daemons and all Login Items are not covered
- 🟡 Linux XDG autostart file names and enabled systemd service unit files; contents are
  not executed or interpreted, and enabled units do not necessarily run at boot
- Linux desktop autostart coverage follows the [freedesktop autostart specification](https://specifications.freedesktop.org/autostart/latest/);
  the inventory intentionally reports candidate files rather than interpreting desktop-entry policy
- ⬜ Security event monitoring and behavior detection
- ⛔ No process termination yet

## 8. Privacy

- 🟡 FileVault, screen lock, guest account, Gatekeeper signals via audit
- ⬜ App permissions, browser extensions, camera/mic/accessibility inventory
- ⛔ No universal tracking-prevention claim

## 9. Account Security

- 🟡 Local MFA, password-manager, recovery, active-session, and phishing checklist;
  marks remain in memory only and are not account findings
- ⬜ Provider integrations, breach notifications, and sign-in investigation
- ⛔ Never collects passwords or authentication codes; no fabricated breaches

## 10. Incident Response

- 🟡 Local incident cases can be created from open posture findings; linked evidence,
  user timeline notes, status history, and local persistence are implemented
- ✅ JSON/HTML case exports with sensitive-data warning
- ⬜ Event correlation, response actions, independent remediation verification
- ⛔ No destructive actions or system changes are performed from incident cases

## 11. Backup and Recovery

- 🟡 Time Machine destination + best-effort latest snapshot (bounded, may be unverified)
- ⬜ Restore verification, recovery instructions, history
- ⛔ Never modifies backups

## 12. Security Toolkit

- 🟡 Local SHA-256 (max 64 MiB), basic metadata, and first-4-KiB signature checks for
  one user-selected file; signature/extension mismatch is informational only
- 🟡 User-triggered DNS resolution and TLS validation for one host on port 443; unit
  checks pass, but a live handshake was not verified in this sandbox
- 🟡 Bounded read-only viewer for recent CyberGates application logs; this is not an
  operating-system security-event viewer
- ⬜ Certificate details beyond leaf fingerprint, IP/domain reputation, decoders, and
  report builder
- ⛔ No exploit, credential-theft, stealth, or destructive tools

## 13. Device Management

- ⛔ No backend, accounts, or cloud sync. Local app is fully independent.

## 14. Reports and History

- ✅ Audit history, findings viewer, activity log
- ✅ Severity and detected-date filters for audit findings
- ✅ Sanitized JSON and HTML export with sensitive-data warning
- 🟡 Audit and incident JSON/HTML reports are implemented; scan reports depend on the
  unavailable malware scanner
- ⬜ OS notification delivery is not implemented; the saved setting is a preference only

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
4. Verified Linux posture adapter and Windows native adapter, tested on each platform.
5. Firewall rule read/apply/revert with impact preview and audit trail.
6. Build remaining toolkit diagnostics and safe response workflows; keep AI and
   multi-device features unavailable until consent, backend, and threat controls exist.
