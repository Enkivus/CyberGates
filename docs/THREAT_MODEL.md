# Threat Model

CyberGates is security-sensitive software that reads local security configuration.
This model covers the current v0.1.0 surface and records controls that are implemented
versus planned. It must be updated whenever a new privileged capability is added.

## Assets

- Local security findings, audit history, and reports (may reveal hostnames, paths,
  network endpoints, and configuration weaknesses).
- The SQLite database, logs, and exported reports on disk.
- Integrity of the score and remediation guidance.
- Future privileged operations (firewall rules, quarantine, process termination).
- User trust: a false "protected" or "clean" claim is itself a safety harm.
- Future signing keys, API keys, and cloud credentials (none exist today).

## Trust boundaries

1. **Webview ↔ Rust backend (IPC).** The UI is untrusted input. Only typed commands
   are exposed; no shell/filesystem plugins.
2. **Rust backend ↔ operating system.** Native tools and APIs are invoked with fixed
   programs and argument arrays; output is untrusted data.
3. **Backend ↔ local database/files.** Paths are app-controlled; reports are written
   only to the app data directory.
4. **Backend ↔ external network.** The only outbound call is the user-triggered
   Homebrew advisory database download over HTTPS. It sends no device data. Future
   reputation checks, AI, and cloud services would cross this boundary.
5. **Application ↔ packaged artifacts.** Installers must be signed and verified;
   current builds are unsigned previews.

## Threats and mitigations

| Threat | Impact | Current mitigation | Status |
|---|---|---|---|
| Command injection via IPC | Arbitrary code execution | No shell plugin; fixed programs + argument arrays; no user-controlled commands | Implemented |
| Path traversal / symlink abuse | Read/write outside intended paths | Report paths are app-generated; `safe_absolute_path` helper validates future file ops; report format allowlist | Partial (file ops limited) |
| Malicious/oversized tool output | Memory exhaustion, UI injection | Output capped (512 KiB default, 8 MiB for `system_profiler`); timeouts on every subprocess; React escapes text | Implemented |
| Unauthorized IPC / parameter abuse | Data tampering, expensive work | Typed commands, clamped limits, setting allowlist, audit concurrency guard | Implemented |
| Database corruption / partial audit | Misleading history | WAL, migrations, transactions, interrupted-audit recovery | Implemented |
| Sensitive data leakage via reports/logs | Privacy harm | Reports warn and are local; logs exclude secrets/content; no telemetry | Partial (reports are sensitive by nature) |
| Malicious or malformed advisory feed | Memory exhaustion, SQL injection, misleading findings | HTTPS-only fixed URL; 64 MiB download cap; 256 MiB unpacked cap; 2 MiB/record cap; no extraction to disk; parameterized SQL; conservative applicability rules | Implemented |
| Supply-chain compromise | Full compromise | Lockfiles, pinned major versions, CI, planned `cargo audit`/`npm audit`; dependency review required | Partial |
| Unsigned updates / installers | Impostor binaries | No updater; builds explicitly labeled unsigned | Planned (signing) |
| Privilege escalation | System compromise | App runs as the user; no root helper; no privileged writes | Implemented by omission |
| Spoofed security findings / false assurance | User makes bad decisions | Findings require evidence; unavailable checks excluded; UI states limitations | Implemented |
| Prompt injection via logs/filenames (future AI) | Assistant misbehaves | No AI provider exists; future design treats data as untrusted and actions as separate | Planned |
| Malicious report/HTML injection | Code execution in exported report | All report fields HTML-escaped; local static file only | Implemented |
| Quarantine race/symlink attack (future) | File destruction / escape | Not implemented; mandatory design controls documented | Planned |
| Firewall misconfiguration by app (future) | Loss of connectivity / exposure | Not implemented; no automatic broad changes; undo/audit required | Planned |

## Explicit non-goals

- CyberGates does not exploit vulnerabilities, intercept encrypted traffic, collect
  browsing content, harvest credentials, or provide stealth/evasion tooling.
- It does not replace the operating system firewall, endpoint protection, or backups.
- It does not guarantee a device is malware-free; unimplemented checks are excluded.

## Residual risks (current)

- Native tool output parsing can break across OS versions; checks then become
  unavailable rather than guessing, but false pass/fail is still possible and needs
  ongoing test coverage.
- A malicious local process with the user's privileges can alter the user's own data
  or tools; CyberGates cannot defend a fully compromised user session.
- Unsigned preview builds could be tampered with; only obtain them from a trusted
  build. Signing/notarization is not yet configured.
- Reports contain sensitive data and are protected only by filesystem permissions.
- macOS privacy controls may hide data; those checks report unavailable.

## Future privileged operations — required controls

Before adding firewall changes, quarantine, process termination, network isolation, or
updates:

1. Separate narrow privileged helper with authenticated IPC (never expose raw commands).
2. Validate canonical paths, reject symlinks where unsafe, and guard against races.
3. Show an impact and consequence explanation with explicit confirmation.
4. Support reversal/restore and record success/failure in the audit trail.
5. Verify the outcome independently before claiming success.
6. Sign and verify updates; document key custody and rotation.

## Review checklist

- Does this change add a new trust boundary or privilege?
- Is every external input bounded, validated, and escaped?
- Can the feature fail closed and report "unknown" instead of "safe"?
- Is there an audit record for any state-changing operation?
- Are platform limitations disclosed rather than hidden?
- Do tests cover hostile input, cancellation, and permission failure?
