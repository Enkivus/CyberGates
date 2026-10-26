# Architecture

## Overview

CyberGates is a Tauri 2 desktop application:

- **Rust backend** (`src-tauri/`) owns all system access, persistence, validation,
  scoring, and report generation.
- **React + TypeScript UI** (`src/`) renders backend data. The only direct local-file
  access is a user-selected file through the browser file picker for bounded hashing
  and header inspection; the webview cannot browse arbitrary paths.
- **Typed IPC** connects them. The webview receives no filesystem, shell, or process
  plugin permissions (`src-tauri/capabilities/default.json` grants only `core:default`).

```
┌──────────────────────────── React / TypeScript ────────────────────────────┐
│ Sidebar (15 sections) · Overview · Monitoring · Network · Reports · Settings │
│ `src/lib/api.ts` — typed invoke wrappers, error normalization                │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ Tauri commands (JSON DTOs, camelCase)
┌──────────────────────────────────▼──────────────────────────────────────────┐
│ commands/        thin handlers: validate → service → DTO                    │
│ services/        audit, system, network, advisories, modules, reports        │
│ core/scoring     deterministic weighted score + finding derivation          │
│ platform/        trait PlatformAudit; macOS adapter; unsupported fallback    │
│ security/        direct process runner (timeouts, no shell), validation      │
│ db/              SQLite, migrations, repositories, audit log, retention      │
│ error.rs         typed errors serialized as { code, message }                │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ direct process execution, read-only
┌──────────────────────────────────▼──────────────────────────────────────────┐
│ macOS native tools: socketfilterfw, fdesetup, csrutil, spctl, softwareupdate │
│ sysadminctl, launchctl, lsof, ifconfig, scutil, tmutil, defaults             │
│ optional HTTPS download: Homebrew OSV advisory database (user-triggered)      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Backend modules

| Module | Responsibility |
|---|---|
| `commands` | Tauri command surface. Validates input, clamps limits, delegates. |
| `services::audit` | Runs an audit, persists it, resolves absent findings, builds dashboard. |
| `services::system` | Host inventory and process sampling via `sysinfo`. |
| `services::network` | Read-only connection and network configuration inventory via platform adapter. |
| `services::advisories` | Downloads/indexes Homebrew's OSV feed; conservative local matching. |
| `services::reports` | Sanitized JSON/HTML audit and incident report generation into the app data directory. |
| `services::logs` | Bounded read-only access to recent CyberGates-owned log files; rejects symlinks and does not expose OS event logs. |
| `services::modules` | Honest per-module capability status shown in the UI. |
| `core::scoring` | Pure scoring and finding construction; unit-tested. |
| `platform` | `PlatformAudit` trait; macOS posture and inventory adapter, Linux read-only package/network/startup/current-user systemd inventories, and unsupported fallback. Linux posture checks remain unavailable. |
| `security::process` | Spawns programs with argument arrays, hard timeout, output cap. |
| `security::validate` | Input bounds, settings allowlist, report format, path helpers. |
| `db` | Migrations, audit/finding/settings/log repositories, retention pruning. |

## Data flow: audit

1. UI invokes `run_audit`. A process-wide atomic rejects concurrent audits.
2. The command moves work to `spawn_blocking`; the webview stays responsive.
3. `audit::execute` records a `running` audit, runs the platform checks, computes the
   score, inserts findings, resolves findings absent from the new audit, and marks the
   audit `completed` with factors serialized as JSON.
4. The dashboard is rebuilt from SQLite and returned.
5. UI renders only persisted, evidence-backed results.

If the app exits mid-audit, startup marks `running` audits as `interrupted`; no
partial results are presented as complete.

## Scoring model

- Each check declares an explicit weight and severity.
- Pass = full weight, Warning = half, Fail = zero.
- Unavailable / NotApplicable checks are excluded from both numerator and denominator.
- Score = round(100 × earned / evaluated); `null` when nothing is evaluable.
- Labels: ≥90 Excellent, ≥75 Good, ≥50 Needs attention, otherwise At risk.
- Findings are created only for Warning/Fail checks and carry evidence, explanation,
  remediation, verification, source, and timestamp.
- The model is deterministic and covered by unit tests (`core/scoring.rs`).

This makes missing platform permissions visible instead of silently changing the
score, and prevents fabricated "protection" claims.

## Data flow: advisory matching

1. The user explicitly updates the advisory database. Rust downloads Homebrew's
   OSV-format tarball over HTTPS (fixed URL, 64 MiB cap), parses it in memory, and
   replaces the local advisory index in SQLite inside a transaction.
2. Matching reads installed Homebrew packages and local advisory rows only; it does not
   send inventory to a server.
3. Homebrew documents generated records' fixed boundary as the currently shipped version,
   an approximation rather than the exact fixing version. CyberGates marks generated
   records unverified. Only non-generated records with same-upstream-version revision
   patches and `fix=patch` are eligible as candidate matches.

## Database schema (v4)

- `audits(id, started_at, finished_at, score, status, platform, factors_json)`
- `findings(id, audit_id → audits, check_id, title, severity, status, category,
  evidence, explanation, remediation, verification, source, detected_at, resolved_at)`
- `settings(key, value)` — seeded defaults; allowlisted updates
- `audit_log(id, at, action, detail, outcome)`
- `advisories(id, package, introduced, fixed, fix_kind, summary, severity,
  aliases_json, references_json, modified)` — downloaded feed index
- `advisory_meta(key, value)` — source, fetched_at, counts, scope
- `incidents(id, title, severity, status, created_at, updated_at, closed_at)` — local
  case records created from findings
- `incident_findings(incident_id, finding_id)` — retained evidence links; links cascade
  away if the underlying audit finding expires under retention
- `incident_events(id, incident_id, at, event_type, detail)` — user notes and status
  changes; no system-changing response action is recorded as executed

Migrations are versioned with `rusqlite_migration`. Foreign keys are enabled and WAL
mode is on. Retention pruning deletes old audits (findings cascade) and log entries.

## Platform model

`PlatformAudit` exposes `platform_name`, `supported`, `notes`, `audit`, `connections`,
`installed_apps`, `firewall_snapshot`, and bounded startup/service inventories. Each OS
must implement and be tested before claiming posture-audit support.

- **macOS:** read-only native tooling; implemented.
- **Linux:** read-only network address/DNS configuration, XDG autostart names, enabled
  systemd unit files, and current-user loaded service states are available. The posture
  audit remains unavailable and makes no security score or protection claim.
- **Windows:** current-user and local-machine Run/RunOnce registry value names are
  listed read-only. Configured commands, startup folders, scheduled tasks, and service
  state are not inspected; the posture audit remains unavailable and no score or
  protection claim is made.

Adding an adapter must not change the UI contract; capability states are data.

## IPC and privilege

- No shell, filesystem, HTTP, or opener plugin is exposed to the webview.
- A user can select one file for local SHA-256 and signature inspection. Hash input is
  capped at 64 MiB; signature inspection reads only the first 4 KiB through the browser
  file input. The JSON structure inspector separately reads at most 1 MiB, reports only
  top-level structure and value types, and omits values. Contents are never sent over
  IPC or uploaded, and the app never executes the selected file.
- Commands accept typed parameters; IDs, formats, and setting keys are validated.
- Process execution lives entirely in Rust, uses argument arrays (no shell string
  concatenation), and imposes timeouts/output caps.
- The app runs as the user; it does not request root. Future privileged operations
  require a separately designed helper with authentication and auditing.
- Errors return `{ code, message }`; no internal paths or secrets are exposed in UI
  errors beyond intentional storage locations shown in Settings.

## Frontend structure

- `components/Layout.tsx` — collapsible sidebar, 15-section navigation, theme switch.
- `components/ui.tsx` — design system primitives (panels, badges, score ring, states).
- `components/ModulePage.tsx` — honest status layout for unimplemented/partial modules.
- `features/overview` — dashboard, score explanation, findings, posture checks.
- `features/monitoring` — process table plus macOS launchd and Linux XDG/systemd
  startup and service inventories.
- `features/network` — read-only connection and interface/DNS resolver inventory where
  supported by the native platform adapter.
- `features/firewall` — read-only macOS Application Firewall state/app rules and partial
  Linux firewall-manager observations.
- `features/vulnerabilities` — software inventory and optional Homebrew advisories.
- `features/reports` — audit history, findings viewer, exports, activity log.
- `features/settings` — theme, retention, preferences, storage, limitations.
- `features/toolkit` — bounded local file hashing, metadata, header signatures, and
  user-triggered DNS/TLS diagnostics.
- `features/modules` — per-module capability descriptions.

Business logic stays in Rust; the UI formats and presents.

## Adding a feature safely

1. Add a service with a testable interface; keep OS calls in `platform`.
2. Add typed DTOs and a thin command; validate every input.
3. Persist results with a migration if needed.
4. Add Rust unit/integration tests, then UI states (loading/empty/error/permission).
5. Update `docs/FEATURE_STATUS.md`, `docs/CAPABILITY_MATRIX.md`, README, and the local
   `instructions.md` blueprint.
6. Never mark a module "available" until its real path is verified end-to-end.
