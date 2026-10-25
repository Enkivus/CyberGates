# CyberGates

CyberGates is a local-first desktop app for inspecting a computer’s security
configuration and understanding the evidence behind each result. It is built with
Tauri 2, Rust, React, and TypeScript.

> **Preview software — v0.1.0.** CyberGates currently has a verified native security
> adapter for macOS. Windows and Linux builds do not yet perform native posture audits.
> This is not antivirus software and does not claim that a device is malware-free.

## What works today

- Explainable macOS posture audit for firewall state, FileVault, SIP, Gatekeeper,
  supported OS version, screen lock, automatic updates, remote access, guest account,
  backup metadata, and XProtect presence.
- System and process inventory, launchd startup-file inventory, and read-only TCP/UDP
  socket inventory.
- Read-only network interface and configured DNS resolver inventory on macOS. Resolver
  addresses are shown as configured; CyberGates does not rate their trustworthiness.
- Installed application and Homebrew inventory, plus optional Homebrew advisory
  matching. Matching is intentionally limited and does not cover all applications or
  package managers.
- Read-only macOS Application Firewall settings and per-application exceptions.
- Local audit history, findings, configurable retention, activity log, and JSON/HTML
  reports.
- Dark and light themes, searchable views, and explicit unavailable/planned states for
  capabilities that are not operational.

## Not implemented

Malware scanning, real-time protection, quarantine, broad vulnerability assessment,
DNS reputation, network discovery or port scanning, firewall changes, event monitoring,
incident response, app-permission auditing, backup restore verification, account
integrations, AI, cloud sync, and multi-device management are not implemented. Read
[`docs/FEATURE_STATUS.md`](docs/FEATURE_STATUS.md) and
[`docs/CAPABILITY_MATRIX.md`](docs/CAPABILITY_MATRIX.md) for scope and platform status.

## Requirements

- Rust stable and Node.js 22 or newer with npm
- Tauri platform prerequisites:
  - **macOS:** Xcode Command Line Tools
  - **Windows:** Microsoft C++ Build Tools and WebView2
  - **Linux:** WebKitGTK 4.1, GTK, AppIndicator, OpenSSL, and build tools. The CI
    workflow lists the Ubuntu packages used for builds.

## Run locally

```bash
npm ci
npm run tauri dev
```

`npm run dev` starts the frontend by itself; native data commands require the Tauri
backend.

## Build

```bash
npm run tauri build
```

The Tauri bundler writes platform artifacts under `src-tauri/target/release/bundle/`.
Preview artifacts are unsigned and not notarized. See
[`docs/SECURITY.md`](docs/SECURITY.md) before distributing a build.

## Verify changes

```bash
npm run typecheck
npm run lint
npm test
npm run build
cargo fmt --check --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

The GitHub Actions matrix is defined in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Passing local checks does not
mean the cross-platform matrix has run; check the repository’s Actions page for its
current status.

## Local data and privacy

CyberGates stores its SQLite database, audit history, settings, and reports in the
application data directory selected by Tauri. On macOS this is normally
`~/Library/Application Support/com.cybergates.app/`; logs are normally in
`~/Library/Logs/com.cybergates.app/`. Unix data directories are restricted to the
current user. Reports may include hostnames, paths, processes, and network details;
review them before sharing.

The app has no active telemetry, cloud sync, or AI service. Updating the optional
Homebrew advisory database is the only feature that makes an outbound request; it
downloads public advisory data over HTTPS and does not upload device inventory. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for trust boundaries and limitations.

## Contributing

Keep findings evidence-based and make unsupported checks explicitly unavailable. Do
not add destructive actions, broad scans, or external data uploads without documenting
their scope, privacy impact, failure behavior, and verification. See the architecture,
security, and feature-status documents in [`docs/`](docs/).

## Security reports

Please report vulnerabilities privately through the repository host’s security
reporting feature rather than posting exploit details publicly. The project has no
published bug bounty or response SLA. More information is in
[`docs/SECURITY.md`](docs/SECURITY.md).

## License

See [`LICENSE`](LICENSE).
