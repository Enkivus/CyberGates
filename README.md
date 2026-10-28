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
- System and process inventory, macOS launchd startup-file and current-user loaded-job
  inventories, and read-only TCP/UDP socket inventory.
- Windows read-only startup inventory for current-user and local-machine Run/RunOnce
  registry entry names. Command data is omitted; startup folders, scheduled tasks,
  services, and Windows posture checks remain unavailable.
- Linux read-only interface/DNS configuration, XDG autostart file names, enabled
  systemd service unit files, and current-user loaded service states. Linux posture
  security checks and socket ownership are not yet implemented.
- Read-only network interface and configured DNS resolver inventory on macOS and Linux.
  Linux may expose only a local stub resolver. Resolver addresses are shown as
  configured; CyberGates does not rate their trustworthiness.
- Installed application and Homebrew inventory, plus optional Homebrew advisory
  matching. Automatically generated Homebrew fixed boundaries are treated as
  unverified; matching only considers reviewed records with a same-version revision
  patch. This does not cover all applications or package managers.
- Linux installed-package name and version inventory through dpkg, RPM, or pacman when
  one of those package databases is available. Linux packages are not matched against
  vulnerability advisories except for the limited Debian check below.
- Manual, user-confirmed OSV.dev advisory lookup for recognized Debian numeric releases.
  It sends Debian source package names, versions, and release ID to OSV.dev and uses
  OSV's version-aware result. RPM, pacman, other distributions, and application bundles
  are not covered; a clean result is not proof of safety.
- Read-only macOS Application Firewall settings and per-application exceptions, plus
  partial Linux UFW/firewalld/nftables observations. Neither is a complete firewall
  policy audit, and CyberGates does not change firewall settings.
- Local SHA-256 hashing (up to 64 MiB) and bounded header-signature inspection for a
  user-selected file; contents are read in the webview and never uploaded or executed.
  Signature and extension checks are best-effort and do not determine whether a file is
  safe.
- A bounded JSON structure inspector for selected UTF-8 JSON files up to 1 MiB. It
  reports top-level key and value types without displaying values, executing content,
  or validating a schema.
- User-triggered DNS resolution and TLS certificate validation for one host on port
  443. Host diagnostics disclose the name to the configured resolver and target host,
  send no HTTP request, and do not provide reputation verdicts.
- A bounded, read-only viewer for recent CyberGates application logs. It does not show
  operating-system security events; review local paths and error details before sharing.
- Local audit history, findings with severity/date filters, configurable retention,
  activity log, full and filtered JSON/HTML audit reports, and incident reports.
- Optional in-app notice after a manual audit finds a new high or critical finding. The
  notice omits finding details; operating-system notification delivery is not implemented.
- Local incident cases created from open posture findings, with linked evidence,
  user-entered timeline notes, auditable status history, and private JSON/HTML exports.
  Cases do not perform or verify system response actions.
- A private account-security checklist based on CISA and NIST guidance. Checklist marks
  are temporary and do not inspect accounts, collect credentials, or persist.
- Dark and light themes, searchable views, and explicit unavailable/planned states for
  capabilities that are not operational.
- A restrictive production webview content security policy that blocks inline styles.

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

The app has no active telemetry, cloud sync, or AI service. Network requests happen
only when you update the optional Homebrew advisory database, confirm a Debian OSV.dev
package lookup, or submit a host in DNS/TLS diagnostics. The Homebrew update downloads
public data without uploading inventory. The Debian lookup sends source package names,
versions, and release ID to OSV.dev. Host diagnostics disclose the entered host to your
configured DNS resolver and open a TLS connection to that host on port 443. See
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
