import { ModulePage } from "../../components/ModulePage";

export function ThreatProtection() {
  return (
    <ModulePage
      moduleId="threat-protection"
      title="Threat Protection"
      subtitle="Malware scanning integrations, real-time protection, and quarantine. CyberGates will use vetted engines and native platform facilities, never a home-made scanner."
      capabilities={[
        {
          label: "Apple XProtect presence check",
          state: "partial",
          detail:
            "The posture audit verifies XProtect files exist at Apple's system paths. It does not inspect signatures or detection history.",
        },
        {
          label: "File and directory malware scanning",
          state: "planned",
          detail:
            "No scanning engine is integrated. There is no scan button yet because a disabled or simulated scanner would be misleading.",
        },
        {
          label: "Real-time protection",
          state: "planned",
          detail:
            "Requires a verified event source, detection engine, response path, and explicit user permission. None are implemented.",
        },
        {
          label: "Quarantine and restore",
          state: "planned",
          detail:
            "Not implemented. When built, quarantine will validate paths, resist symlink/race attacks, preserve restore ability, and write an audit trail.",
        },
        {
          label: "Scheduled scans",
          state: "planned",
          detail:
            "Not implemented. Scheduling depends on the scan engine and a background execution model that does not exist yet.",
        },
      ]}
      safety="CyberGates will never disable or replace your existing endpoint protection. A screen that says 'protected' without a working engine and verified events would be dangerous, so the feature stays visibly unavailable until it is real."
    />
  );
}

export function Scanner() {
  return (
    <ModulePage
      moduleId="scanner"
      title="Security Scanner"
      subtitle="On-demand and scheduled malware scans with progress, cancellation, risk categories, and scan history."
      capabilities={[
        {
          label: "User-initiated file and directory scans",
          state: "planned",
          detail:
            "No scanning engine is integrated yet. The posture audit in Overview is a configuration review, not a malware scan.",
        },
        {
          label: "Scan progress and cancellation",
          state: "planned",
          detail:
            "Planned with a cancellable background task and bounded concurrency once a real engine exists.",
        },
        {
          label: "Scheduled scans",
          state: "planned",
          detail:
            "Requires the scan engine, a scheduler, and reliable background execution.",
        },
        {
          label: "Results, history, and export",
          state: "planned",
          detail:
            "Scan results will be persisted in SQLite and exportable alongside audit reports.",
        },
        {
          label: "Quarantine workflow",
          state: "planned",
          detail:
            "Not implemented. Quarantine will never silently delete files and will support review and restoration.",
        },
      ]}
      safety="CyberGates will not display a fake progress bar, random detections, or simulated scan results. Until a real engine is integrated and tested, this module performs no scanning."
    />
  );
}

export function FirewallPage() {
  return (
    <ModulePage
      moduleId="firewall"
      title="Firewall"
      subtitle="Native firewall visibility and, eventually, narrowly scoped rule management with impact preview and verification."
      capabilities={[
        {
          label: "Firewall enabled status",
          state: "partial",
          detail:
            "The Overview audit reads the macOS application firewall state and reports it with evidence.",
        },
        {
          label: "Stealth mode status",
          state: "partial",
          detail:
            "The audit also reads stealth mode. Both checks are read-only.",
        },
        {
          label: "Rule inspection",
          state: "planned",
          detail:
            "No rule list is available yet. Rule parsing and risky-configuration explanation are planned.",
        },
        {
          label: "Apply, revert, and verify changes",
          state: "planned",
          detail:
            "Not implemented. Future changes will require confirmation, an impact explanation, an undo path, and an audit record.",
        },
      ]}
      safety="CyberGates will never flush all firewall rules, disable the firewall, or make broad network changes as a shortcut. Any future privileged change must be explicit and reversible."
    />
  );
}

export function Privacy() {
  return (
    <ModulePage
      moduleId="privacy"
      title="Privacy"
      subtitle="Supported privacy and physical-access signals, reported only when the operating system actually exposes them."
      capabilities={[
        {
          label: "Disk encryption, screen lock, guest account",
          state: "partial",
          detail:
            "FileVault, screen-lock delay, and the guest-account flag are included in the macOS posture audit.",
        },
        {
          label: "Application permission inventory",
          state: "planned",
          detail:
            "Camera, microphone, accessibility, and other permission data are not audited yet.",
        },
        {
          label: "Startup items and browser extensions",
          state: "planned",
          detail:
            "Not implemented. Future adapters must respect platform privacy protections.",
        },
        {
          label: "Downloaded app signature checks",
          state: "planned",
          detail:
            "Gatekeeper status is audited, but per-app signature inspection is not implemented.",
        },
      ]}
      safety="CyberGates does not promise universal tracking protection or access to data the OS hides. When a setting cannot be inspected, the UI will say so and may offer manual verification steps rather than guessing."
    />
  );
}

export function AccountSecurity() {
  return (
    <ModulePage
      moduleId="account"
      title="Account Security"
      subtitle="Optional guidance and authorized integrations for account hygiene. No credentials are ever collected."
      capabilities={[
        {
          label: "MFA and account-security checklists",
          state: "planned",
          detail: "Guidance content is not built yet.",
        },
        {
          label: "Breached-account notifications",
          state: "planned",
          detail:
            "Requires an authorized provider integration and explicit consent. No breach data is collected today.",
        },
        {
          label: "Suspicious sign-in investigation",
          state: "planned",
          detail:
            "Planned only through supported provider APIs, never by scraping private accounts.",
        },
      ]}
      safety="CyberGates will never ask for your primary account password, store authentication codes, or fabricate breach records. This module is entirely dormant until a legitimate integration is implemented."
    />
  );
}

export function IncidentResponse() {
  return (
    <ModulePage
      moduleId="incident-response"
      title="Incident Response"
      subtitle="Evidence-based incident timelines and narrowly scoped response actions with verification."
      capabilities={[
        {
          label: "Incident creation from findings",
          state: "planned",
          detail:
            "Findings are currently reviewed in Overview and Reports, but cannot be promoted into an incident.",
        },
        {
          label: "Evidence timeline and correlation",
          state: "planned",
          detail:
            "No event monitor exists yet, so there is no incident timeline to correlate.",
        },
        {
          label: "Response actions",
          state: "planned",
          detail:
            "Process termination, quarantine, reversible configuration changes, network isolation, and diagnostic bundles are not implemented.",
        },
        {
          label: "Verification and closure",
          state: "planned",
          detail:
            "CyberGates will not claim a threat is removed until the relevant verification checks pass.",
        },
      ]}
      safety="Disruptive actions will always require explicit confirmation, a consequence explanation, least-privilege execution, and a record of success or failure. Nothing in this module can change your system today."
    />
  );
}

export function Backup() {
  return (
    <ModulePage
      moduleId="backup"
      title="Backup and Recovery"
      subtitle="Backup readiness signals, clearly separated from proof that a restore works."
      capabilities={[
        {
          label: "Time Machine destination metadata",
          state: "partial",
          detail:
            "The macOS audit checks whether a destination is configured and attempts to read the latest snapshot with a timeout.",
        },
        {
          label: "Backup staleness assessment",
          state: "partial",
          detail:
            "Recency is reported when the native tool responds. A timeout is treated as unverified, not as success.",
        },
        {
          label: "Restore verification",
          state: "planned",
          detail:
            "Checking metadata is not a restore test. CyberGates does not currently verify that data can be recovered.",
        },
        {
          label: "Recovery instructions and history",
          state: "planned",
          detail: "Not implemented.",
        },
      ]}
      safety="CyberGates never deletes, rewrites, or synchronizes over backup copies. A configured backup destination is not presented as guaranteed recoverability."
    />
  );
}

export function Toolkit() {
  return (
    <ModulePage
      moduleId="toolkit"
      title="Security Toolkit"
      subtitle="Defensive utilities for hashing, inspection, diagnostics, and report generation."
      capabilities={[
        {
          label: "File hashing and metadata",
          state: "planned",
          detail:
            "No hashing UI yet. Cryptographic hashing will use vetted libraries with bounded file reads.",
        },
        {
          label: "Signature and certificate inspection",
          state: "planned",
          detail: "Not implemented.",
        },
        {
          label: "DNS, IP/domain, and TLS diagnostics",
          state: "planned",
          detail:
            "Planned with explicit timeouts and clear separation between local facts and external data.",
        },
        {
          label: "Log viewer and decoding utilities",
          state: "planned",
          detail: "Not implemented.",
        },
        {
          label: "Safe file analysis",
          state: "planned",
          detail:
            "Will inspect without executing suspicious files. No exploit, credential-theft, or stealth tooling will ever be included.",
        },
      ]}
      safety="Every tool input will be validated and every external request bounded by timeouts and size limits. The toolkit will remain defensive-only."
    />
  );
}

export function Devices() {
  return (
    <ModulePage
      moduleId="devices"
      title="Device Management"
      subtitle="Optional multi-device visibility and policy management. This requires a separate authenticated backend that does not exist yet."
      capabilities={[
        {
          label: "Device registration and consent",
          state: "unavailable",
          detail: "No backend, accounts, or registration flow exist.",
        },
        {
          label: "Centralized reporting and policies",
          state: "unavailable",
          detail:
            "Not claimed. The local desktop app remains fully useful without any cloud service.",
        },
        {
          label: "Secure communications and revocation",
          state: "unavailable",
          detail:
            "Will require authentication, authorization, transport security, and key rotation design before implementation.",
        },
      ]}
      safety="Cloud synchronization is not operational. CyberGates makes no network calls for device management, and will not until a documented, authenticated service is built and reviewed."
    />
  );
}
