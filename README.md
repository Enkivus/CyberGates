# CyberGates

Cross-platform, local-first cybersecurity command center. CyberGates inspects this
device's security configuration, explains what it finds, and tracks the results over
time. The desktop shell is Tauri 2, the backend is Rust, and the UI is React +
TypeScript.

> **Status: early preview (v0.1.0).** Posture auditing, process/connection inventory,
> installed-software inventory, persisted findings, and JSON/HTML audit reports are
> real. Malware scanning, vulnerability advisory matching, firewall changes, event
> monitoring, incident response, AI, and multi-device management are **not
> implemented**. The UI states this explicitly.

CyberGates never fabricates scan results, protection status, or scores. Unsupported
capabilities are shown as unavailable or planned.

## Implemented today

- Explainable security score derived from weighted, documented checks
- macOS posture audit: application firewall + stealth mode, FileVault, SIP,
  Gatekeeper, macOS version support, screen-lock delay, automatic update schedule,
  SSH/screen-sharing exposure, guest account, Time Machine metadata, XProtect presence
- System inventory (OS, kernel, CPU, memory, uptime)
- Live process inventory with executable paths
- Read-only TCP/UDP connection inventory with owning process where exposed
- Installed software inventory (macOS applications + Homebrew) with signature/trust data
- Read-only macOS Application Firewall snapshot with per-app allow/block rules
- SQLite persistence with migrations, findings history, retention pruning, audit log
- Sanitized JSON and HTML audit reports
- Dark/light UI, all 15 product sections discoverable, honest capability states
- Rust unit tests and frontend tests

## Not implemented yet

Malware/file scanning, real-time protection, quarantine, vulnerability advisory
matching/feeds, firewall rule changes, event monitoring, incident response actions, privacy/app
permission auditing, backup restore verification, security toolkit, account
integrations, AI assistant, and multi-device/cloud features. Windows and Linux
currently have **no native audit adapter**; they start with an explicit unsupported
state rather than guessed results.

See [`docs/FEATURE_STATUS.md`](docs/FEATURE_STATUS.md) and
[`docs/CAPABILITY_MATRIX.md`](docs/CAPABILITY_MATRIX.md).

## Requirements

- Rust stable (tested with 1.99)
- Node.js 22+ and npm
- Platform toolchain for Tauri:
  - **macOS:** Xcode Command Line Tools (`xcode-select --install`)
  - **Windows:** Microsoft C++ Build Tools + WebView2 (bundled with modern Windows)
  - **Linux:** `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`,
    `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`,
    `patchelf`

## Development

```bash
npm install
npm run tauri dev
```

The frontend alone can be run with `npm run dev`, but every data view requires the
Rust backend and will show an honest backend-unavailable error in a plain browser.

## Build

```bash
npm run tauri build           # release app + platform bundles
npm run tauri build -- --debug
```

Artifacts (current machine):

- macOS app: `src-tauri/target/release/bundle/macos/CyberGates.app`
- macOS DMG: `src-tauri/target/release/bundle/dmg/`
- Debug builds: replace `release` with `debug`

Packages are **unsigned**. Signing and notarization instructions live in
[`docs/SECURITY.md`](docs/SECURITY.md); never treat an unsigned build as
production-ready.

## Tests and checks

```bash
npm run typecheck
npm run lint
npm test
cargo fmt --check --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

CI runs these on macOS, Windows, and Linux — see `.github/workflows/ci.yml`.

## Local data

| Platform | Data | Logs |
|---|---|---|
| macOS | `~/Library/Application Support/com.cybergates.app/` | `~/Library/Logs/com.cybergates.app/` |
| Windows | `%APPDATA%\com.cybergates.app\` | `%LOCALAPPDATA%\com.cybergates.app\logs\` |
| Linux | `~/.local/share/com.cybergates.app/` | `~/.local/share/com.cybergates.app/logs/` |

The SQLite database stores findings, audits, settings, and the privileged-action
audit log. Exported reports go to the `reports/` subdirectory. Reports may contain
sensitive system information; review before sharing.

## Privacy and security

CyberGates is local-first. No telemetry, cloud sync, or AI provider is active. It
does not read passwords, recovery keys, or authentication codes. Privileged operations
are not exposed to the webview; all data access goes through typed Tauri commands with
validation. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/CAPABILITY_MATRIX.md`](docs/CAPABILITY_MATRIX.md)
- [`docs/FEATURE_STATUS.md`](docs/FEATURE_STATUS.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)

## License

See [`LICENSE`](LICENSE).
