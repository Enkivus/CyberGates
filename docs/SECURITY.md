# Security Policy and Engineering Notes

## Reporting a vulnerability

CyberGates is a security product; please report security issues privately rather than
opening a public issue with exploit details. Use the repository host's private
vulnerability reporting feature or contact the maintainer listed on the repository.
Include affected version, platform, reproduction steps, and impact. Do not test against
systems you do not own or have explicit authorization to assess.

No bug bounty or response SLA is currently published.

## Current security posture

- Local-first: no telemetry, cloud sync, or AI provider is active. Outbound requests
  occur only for a user-triggered Homebrew feed update or host DNS/TLS diagnostic. Host
  diagnostics disclose the submitted name to the configured resolver and target host;
  the app sends no inventory or device identifiers.
- The webview has no shell/filesystem/HTTP plugins; only typed commands are exposed.
- The production webview Content Security Policy disallows inline styles. The UI
  uses external stylesheets and SVG presentation attributes; the development policy
  permits inline styles for the Vite development server only.
- Subprocess execution uses fixed programs and argument arrays with hard timeouts and
  bounded output capture. Executable paths must be absolute, so the inherited `PATH`
  cannot substitute a different binary. Unix subprocesses run in a dedicated process
  group so timeout cleanup also terminates descendants holding captured pipes. No
  shell string construction in production code.
- Unix local-data and report directories use mode `0700`; SQLite database and report
  files use mode `0600`. New files are created exclusively, and existing database
  symlinks are rejected before SQLite opens them.
- SQLite uses migrations, foreign keys, WAL, and transactions. Audit runs are
  serialized; interrupted runs are marked on next startup.
- Report fields are HTML-escaped for HTML exports.
- Logs avoid secrets, credentials, file contents, and full command output by default.
- The app runs with user privileges only. There is no root helper.

## Secrets

- Never commit API keys, signing certificates, private keys, recovery keys, or
  credentials. `.env*`, key/certificate extensions, and `secrets/` are gitignored.
- CyberGates does not currently accept any secret. Future AI/provider keys must be
  supplied by the user at runtime and stored in the OS keychain or an encrypted store,
  never in the repository or plain settings.
- The app never reads or stores passwords, FileVault recovery keys, or MFA codes.

## Code signing and distribution

Current installers are **unsigned preview builds**. Do not describe them as signed,
notarized, or production-ready.

To produce legitimate signed releases, the maintainer must own:

- **macOS:** an Apple Developer ID Application certificate and notarization
  credentials (`APPLE_CERTIFICATE`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
  `APPLE_PASSWORD`, `APPLE_TEAM_ID` or API key equivalents). Configure Tauri's macOS
  signing; verify with `codesign --verify --deep --strict` and `spctl --assess`.
- **Windows:** an Authenticode code-signing certificate and timestamping. Configure
  `certificateThumbprint`/signing in Tauri; verify with `signtool verify /pa`.
- **Linux:** package signing (e.g., GPG for repository packages) and checksums.

Keys and passwords belong in CI secret storage, never in this repository or build
scripts. Rotation and revocation procedures must be documented before public release.

## Updates

There is no auto-updater. When added, updates must be signed, verified before
installation, fail safely, and never downgrade silently. Do not ship an updater that
trusts an unsigned manifest.

## Dependencies

- Lockfiles (`Cargo.lock`, `package-lock.json`) are committed.
- Run before releases:
  ```bash
  cargo audit --manifest-path src-tauri/Cargo.toml
  npm audit
  ```
- Review new dependencies for maintenance, permissions, and transitive weight. Prefer
  vetted platform facilities and standard cryptographic libraries.

## Privileged operations

No privileged operation is currently implemented. Any future operation (firewall
changes, quarantine, process termination, network isolation) must:

1. Live behind a narrow, authenticated service boundary; never pass raw commands from
   the UI.
2. Validate canonical paths and reject symlink/path traversal attacks.
3. Explain impact and consequences; require explicit confirmation for disruptive work.
4. Be reversible where possible and recorded in the local audit log.
5. Independently verify the result before reporting success.
6. Use least privilege; do not run the whole application as root/administrator.

## Data handling

- Local data path and retention are shown in Settings.
- Exported reports may contain hostnames, paths, processes, and network endpoints.
  A warning is embedded in every export.
- Deleting the app data directory removes findings, history, settings, and reports.
  This is irreversible.
- Findings, logs, and reports are not encrypted at rest in v0.1.0. On Unix, the app
  data and log directories are restricted to the current user; the main SQLite file
  and exported reports are also restricted. On Windows, this version relies on the
  permissions inherited from the per-user application-data directories. Do not rely
  on these files for highly sensitive environments. The in-app log viewer reads only
  recent CyberGates log files with output limits; logs can contain local paths or
  error details and should be reviewed before sharing.

## Limitations to disclose to users

- Passing posture checks does not mean the device is malware-free.
- Backup metadata checks do not prove a restore works.
- Malware scanning and broad vulnerability assessment are not implemented. The
  optional Homebrew advisory matcher covers only a narrow, explicitly disclosed case.
- Windows has no verified posture audit or security score; its partial startup view
  lists Run/RunOnce registry value names only. Linux has partial read-only inventories
  but no verified posture audit or security score.
- Unsigned builds have no verified publisher identity.
