# Platform Capability Matrix

Status reflects **verified behavior in this repository as of v0.1.0**. "Unsupported"
means the app runs but reports that no native adapter exists; it makes no security
claims. Do not upgrade a status without building and testing on that platform.

Legend: ✅ implemented and tested · 🟡 partial · ⛔ explicitly unavailable · ⬜ planned

| Capability | macOS | Windows | Linux |
|---|---|---|---|
| App launch / navigation / settings | ✅ | ⬜ not verified | ⬜ not verified |
| Explainable posture score | ✅ | ⛔ no adapter | ⛔ no adapter |
| Application firewall status | ✅ | ⛔ | ⛔ |
| Firewall app-rule inspection | ✅ read-only | ⛔ | ⛔ |
| Firewall stealth mode | ✅ | — | — |
| Firewall rule changes/apply/revert | ⬜ | ⬜ | ⬜ |
| Disk encryption (FileVault/BitLocker/LUKS) | ✅ FileVault | ⛔ | ⛔ |
| OS integrity protection (SIP) | ✅ | — | — |
| Gatekeeper / app verification | ✅ | — | — |
| OS version support check | ✅ | ⛔ | ⛔ |
| Screen-lock configuration | ✅ | ⛔ | ⛔ |
| Automatic update schedule | ✅ | ⛔ | ⛔ |
| Remote login / SSH exposure | ✅ | ⛔ | ⛔ |
| Screen-sharing exposure | ✅ | — | — |
| Guest account | ✅ | ⛔ | ⛔ |
| Backup destination + recency metadata | 🟡 Time Machine | ⛔ | ⛔ |
| Backup restore verification | ⬜ | ⬜ | ⬜ |
| XProtect presence | ✅ | — | — |
| Malware file scanning | ⬜ | ⬜ | ⬜ |
| Real-time protection | ⬜ | ⬜ | ⬜ |
| Quarantine / restore | ⬜ | ⬜ | ⬜ |
| Installed software inventory | ✅ apps + Homebrew | ⛔ | ⛔ |
| Vulnerability advisory matching | 🟡 Homebrew revision patches | ⛔ | ⛔ |
| Advisory database update (manual) | ✅ ~14 MB download | ⛔ | ⛔ |
| Process inventory | ✅ | ⬜ | ⬜ |
| Loaded service inventory | 🟡 current-user launchd jobs | ⬜ | ⬜ |
| Event monitoring / timeline | ⬜ | ⬜ | ⬜ |
| Network connection inventory | ✅ read-only | ⛔ | ⛔ |
| Network interface address inventory | ✅ read-only | ⛔ | ⛔ |
| Configured DNS resolver inventory | ✅ read-only | ⛔ | ⛔ |
| DNS trust / reputation verdicts | ⬜ | ⬜ | ⬜ |
| Network discovery / port scanning | ⬜ | ⬜ | ⬜ |
| Privacy / app permission audit | 🟡 core signals | ⛔ | ⛔ |
| Account security integrations | ⬜ | ⬜ | ⬜ |
| Incident case tracking | 🟡 local findings + notes | 🟡 local findings + notes | 🟡 local findings + notes |
| Security toolkit | ⬜ local file hashing not verified on target OS | 🟡 local file hashing | ⬜ local file hashing not verified on target OS |
| AI assistant | ⬜ | ⬜ | ⬜ |
| Multi-device management | ⛔ no backend | ⛔ | ⛔ |
| Persisted findings / history | ✅ | ✅ (no adapter data) | ✅ (no adapter data) |
| JSON/HTML audit reports | ✅ | ✅ | ✅ |
| CI build verification | ⬜ pending CI | ⬜ pending CI | ⬜ pending CI |
| Signed installer | ⬜ unsigned | ⬜ unsigned | ⬜ unsigned |

## macOS specifics

- Native tools used: `socketfilterfw`, `fdesetup`, `csrutil`, `spctl`,
  `softwareupdate`, `sysadminctl`, `launchctl`, `lsof`, `tmutil`, `defaults`.
- `tmutil latestbackup` may block on network destinations; it is bounded by a timeout
  and reported as "recency unverified" (warning), never as success.
- `sysadminctl` may require privileges on some systems; failures become "unavailable".
- The audit is read-only. No configuration is changed.

## Windows/Linux specifics

- The app compiles and its unsupported adapter reports a single "platform audit
  adapter unavailable" check with score `null`.
- System inventory, process list, and reports still work through cross-platform Rust
  libraries where available.
- Network connection inventory returns empty with an explanatory UI state.
- Adding an adapter requires real, tested implementations; do not guess values.
