# Platform Capability Matrix

Status reflects **verified behavior in this repository as of v0.1.0**. A platform can
have partial read-only inventories while its posture audit remains unavailable; no
security score or protection claim is made for an unverified audit adapter. Do not
upgrade a status without building and testing on that platform.

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
| Installed software inventory | ✅ apps + Homebrew | ⛔ | 🟡 dpkg / RPM / pacman package metadata |
| Vulnerability advisory matching | 🟡 Homebrew revision patches | ⛔ | ⛔ |
| Advisory database update (manual) | ✅ ~14 MB download | ⛔ | ⛔ |
| Process inventory | ✅ | ⬜ | ⬜ |
| Loaded service inventory | 🟡 current-user launchd jobs | ⬜ | 🟡 current-user systemd units |
| Event monitoring / timeline | ⬜ | ⬜ | ⬜ |
| Network connection inventory | ✅ read-only | ⛔ | ⛔ |
| Network interface address inventory | ✅ read-only | ⛔ | 🟡 read-only |
| Configured DNS resolver inventory | ✅ read-only | ⛔ | 🟡 `/etc/resolv.conf` (may be a local stub) |
| Startup inventory | 🟡 launchd files and jobs | ⛔ | 🟡 XDG files and enabled systemd units |
| DNS trust / reputation verdicts | ⬜ | ⬜ | ⬜ |
| Network discovery / port scanning | ⬜ | ⬜ | ⬜ |
| Privacy / app permission audit | 🟡 core signals | ⛔ | ⛔ |
| Account security integrations | ⬜ | ⬜ | ⬜ |
| Incident case tracking | 🟡 local findings + notes | 🟡 local findings + notes | 🟡 local findings + notes |
| Security toolkit | ⬜ local toolkit checks not verified on target OS | 🟡 hashing, bounded file signatures, DNS + TLS checks | ⬜ local toolkit checks not verified on target OS |
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

- Linux exposes read-only interface/DNS, startup-file/enabled-unit, and current-user
  systemd service inventories. Its posture adapter still reports a single
  "platform audit unavailable" check with score `null`.
- Windows has no native adapter and reports a single "platform audit unavailable"
  check with score `null`.
- System inventory, process list, and reports still work through cross-platform Rust
  libraries where available.
- Linux network connection ownership is not implemented; other platforms without a
  provider return an explanatory empty state.
- Adding an adapter requires real, tested implementations; do not guess values.
