import { useState } from "react";
import { ExternalLink, ShieldCheck } from "lucide-react";
import { ModulePage } from "../../components/ModulePage";
import { PageHeader, Panel, PanelHeader } from "../../components/ui";
import { FileHasher } from "../toolkit/FileHasher";
import { HostDiagnostics } from "../toolkit/HostDiagnostics";
import { ApplicationLogs } from "../toolkit/ApplicationLogs";
import { Incidents } from "../incidents/Incidents";

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
  const checks = [
    {
      id: "unique-passwords",
      title: "Use unique passwords stored in a password manager",
      detail: "Prioritize email, financial, and administrator accounts.",
    },
    {
      id: "mfa",
      title: "Enable multifactor authentication",
      detail:
        "Prefer passkeys or security keys where available; use another MFA option if the service does not support them.",
    },
    {
      id: "recovery",
      title: "Review recovery methods and save recovery codes",
      detail:
        "Keep recovery methods current and store codes somewhere separate from the account they recover.",
    },
    {
      id: "sessions",
      title: "Review signed-in devices and active sessions",
      detail:
        "Use the account provider’s security page to sign out sessions or devices you do not recognize.",
    },
    {
      id: "phishing",
      title: "Treat unexpected sign-in prompts and verification codes carefully",
      detail:
        "Do not approve a prompt or share a code you did not request. Open the service directly to investigate.",
    },
  ];
  const [completed, setCompleted] = useState<string[]>([]);

  return (
    <div className="fade-in">
      <PageHeader
        title="Account Security"
        subtitle="A private checklist for reviewing online account protections. CyberGates cannot inspect or verify your accounts."
      />
      <Panel className="mb-5">
        <PanelHeader
          title="Personal checklist"
          description={`${completed.length} of ${checks.length} marked for this session`}
        />
        <div className="divide-y divide-line">
          {checks.map((check) => {
            const checked = completed.includes(check.id);
            return (
              <label
                key={check.id}
                className="flex cursor-pointer items-start gap-3 px-5 py-4 hover:bg-surface-2"
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() =>
                    setCompleted((current) =>
                      checked
                        ? current.filter((id) => id !== check.id)
                        : [...current, check.id],
                    )
                  }
                  className="mt-0.5 h-4 w-4 accent-accent"
                />
                <span>
                  <span className="block text-sm font-medium text-ink">{check.title}</span>
                  <span className="mt-1 block text-xs leading-relaxed text-muted">
                    {check.detail}
                  </span>
                </span>
              </label>
            );
          })}
        </div>
        <p className="border-t border-line px-5 py-3 text-xs text-muted">
          Checklist marks stay in memory for this screen and are cleared when it closes.
          They are not account findings or verified controls.
        </p>
      </Panel>

      <Panel>
        <PanelHeader title="Trusted guidance" description="Opens the source in your browser." />
        <div className="grid gap-3 p-5 sm:grid-cols-2">
          <a
            className="flex items-start gap-3 rounded-xl border border-line bg-surface-2 p-4 hover:border-accent/40"
            href="https://www.cisa.gov/secure-our-world"
            target="_blank"
            rel="noopener noreferrer"
          >
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-hidden />
            <span className="flex-1">
              <span className="block text-sm font-medium text-ink">CISA: Secure Our World</span>
              <span className="mt-1 block text-xs text-muted">
                Password managers, MFA, and phishing awareness.
              </span>
            </span>
            <ExternalLink className="h-3.5 w-3.5 text-faint" aria-hidden />
          </a>
          <a
            className="flex items-start gap-3 rounded-xl border border-line bg-surface-2 p-4 hover:border-accent/40"
            href="https://pages.nist.gov/800-63-4/sp800-63b/authenticators/"
            target="_blank"
            rel="noopener noreferrer"
          >
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-hidden />
            <span className="flex-1">
              <span className="block text-sm font-medium text-ink">NIST: Authentication guidance</span>
              <span className="mt-1 block text-xs text-muted">
                Current digital identity and phishing-resistance guidance.
              </span>
            </span>
            <ExternalLink className="h-3.5 w-3.5 text-faint" aria-hidden />
          </a>
        </div>
        <p className="border-t border-line px-5 py-3 text-xs text-muted">
          No credentials, codes, account identifiers, or checklist marks are sent to
          CyberGates or stored. Provider integrations and breach monitoring are not
          available.
        </p>
      </Panel>
    </div>
  );
}

export function IncidentResponse() {
  return <Incidents />;
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
    <div className="space-y-5">
      <FileHasher />
      <HostDiagnostics />
      <ApplicationLogs />
    </div>
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
