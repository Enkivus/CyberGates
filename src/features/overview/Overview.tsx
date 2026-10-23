import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Cpu,
  Flame,
  HardDrive,
  Lock,
  RefreshCw,
  ScanLine,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { api } from "../../lib/api";
import type { CheckStatus, Dashboard, ScoreFactor } from "../../lib/types";
import {
  formatDateTime,
  formatRelative,
  formatUptime,
  severityLabel,
} from "../../lib/format";
import {
  CheckIcon,
  EmptyState,
  ErrorState,
  InfoRow,
  KpiCard,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
  ScoreRing,
  SeverityBadge,
} from "../../components/ui";

function factorById(dashboard: Dashboard, id: string): ScoreFactor | undefined {
  return dashboard.factors.find((factor) => factor.id === id);
}

function statusWord(status: CheckStatus | undefined): string {
  switch (status) {
    case "pass":
      return "Enabled";
    case "warning":
      return "Review";
    case "fail":
      return "Disabled";
    case "unavailable":
      return "Unavailable";
    case "not_applicable":
      return "N/A";
    default:
      return "Unknown";
  }
}

export function Overview() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const autoRan = useRef(false);

  const runAudit = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const result = await api.runAudit();
      setDashboard(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getDashboard();
      setDashboard(result);
      const needsFirstAudit =
        !result.lastAudit ||
        (result.lastAudit.status !== "completed" &&
          result.lastAudit.status !== "interrupted");
      if (needsFirstAudit && !autoRan.current) {
        autoRan.current = true;
        setLoading(false);
        await runAudit();
        return;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [runAudit]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !dashboard) {
    return (
      <div>
        <PageHeader
          title="Overview"
          subtitle="Your device's security posture, explained."
        />
        <Panel>
          <LoadingState label="Loading local security posture" />
        </Panel>
      </div>
    );
  }

  if (error && !dashboard) {
    return (
      <div>
        <PageHeader title="Overview" />
        <ErrorState message={error} onRetry={() => void load()} />
      </div>
    );
  }

  if (!dashboard) {
    return <ErrorState message="No dashboard data available." onRetry={() => void load()} />;
  }

  const firewall = factorById(dashboard, "macos.firewall");
  const filevault = factorById(dashboard, "macos.filevault");
  const updates = factorById(dashboard, "macos.auto_updates");
  const findings = dashboard.findings.filter((finding) => !finding.resolvedAt);
  const openHigh = dashboard.counts.critical + dashboard.counts.high;
  const unavailable = dashboard.factors.filter(
    (factor) => factor.status === "unavailable" || factor.status === "not_applicable",
  ).length;

  return (
    <div className="fade-in">
      <PageHeader
        title="Security posture"
        subtitle="A local, evidence-based view of this device. Every check below was read from your system — nothing is simulated."
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void runAudit()}
            disabled={running}
          >
            <RefreshCw className={`h-4 w-4 ${running ? "animate-spin" : ""}`} aria-hidden />
            {running ? "Auditing…" : "Re-run audit"}
          </button>
        }
      />

      {!dashboard.system.supported ? (
        <div className="mb-5 flex items-start gap-3 rounded-xl border border-warn/30 bg-warn-soft p-4">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-warn" aria-hidden />
          <div>
            <p className="text-sm font-semibold text-ink">
              Native audit unavailable on {dashboard.system.platform}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-muted">
              No security claims are made for this platform. The installed adapter only
              reports that checks are unimplemented instead of guessing.
            </p>
          </div>
        </div>
      ) : null}

      {running ? (
        <Panel className="mb-5 overflow-hidden">
          <div className="p-4">
            <div className="mb-3 flex items-center gap-2 text-xs font-medium text-ink">
              <ScanLine className="h-4 w-4 text-accent" aria-hidden />
              Reading native security configuration…
            </div>
            <div className="scan-indeterminate h-1.5 rounded-full bg-surface-3" />
            <p className="mt-2 text-[11px] text-faint">
              Read-only checks. No settings are changed. This can take a few seconds.
            </p>
          </div>
        </Panel>
      ) : null}

      {error ? <ErrorState message={error} onRetry={() => void runAudit()} /> : null}

      <Panel className="mb-5">
        <div className="grid gap-6 p-6 lg:grid-cols-[auto_1fr_auto] lg:items-center">
          <ScoreRing score={dashboard.score} label={dashboard.scoreLabel} />
          <div className="min-w-0">
            <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-faint">
              Explainable security score
            </p>
            <h2 className="mt-1 text-xl font-semibold tracking-tight text-ink">
              {dashboard.scoreLabel === "Unknown"
                ? "Not enough supported checks to score this device"
                : `${dashboard.scoreLabel} posture`}
            </h2>
            <p className="mt-2 max-w-2xl text-xs leading-relaxed text-muted">
              Weighted from {dashboard.factors.length} checks:{" "}
              <span className="font-semibold text-ink">
                {dashboard.earned}/{dashboard.evaluated}
              </span>{" "}
              evaluated points. Passing checks earn full weight, warnings earn half, and
              options the OS does not expose are excluded rather than guessed.{" "}
              {unavailable > 0
                ? `${unavailable} check${unavailable === 1 ? "" : "s"} could not be evaluated on this system.`
                : "All checks were evaluable on this system."}
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-faint">
              <span className="inline-flex items-center gap-1.5">
                <Timer className="h-3.5 w-3.5" aria-hidden />
                Last audit {formatRelative(dashboard.lastAudit?.startedAt)}
              </span>
              <span>{dashboard.factors.length} checks</span>
              <span>{unavailable} excluded</span>
              <span>{formatDateTime(dashboard.generatedAt)}</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 lg:w-[260px]">
            <div className="rounded-xl border border-line bg-surface-2 p-3">
              <p className="text-[10px] uppercase tracking-[0.1em] text-faint">Findings</p>
              <p className="mt-1 text-2xl font-semibold text-ink">{findings.length}</p>
            </div>
            <div className="rounded-xl border border-line bg-surface-2 p-3">
              <p className="text-[10px] uppercase tracking-[0.1em] text-faint">
                High / critical
              </p>
              <p className="mt-1 text-2xl font-semibold text-danger">{openHigh}</p>
            </div>
            <div className="col-span-2 rounded-xl border border-line bg-surface-2 p-3">
              <p className="text-[10px] uppercase tracking-[0.1em] text-faint">
                Audit coverage
              </p>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-3">
                <div
                  className="h-full rounded-full bg-accent"
                  style={{
                    width: `${
                      dashboard.factors.length
                        ? Math.round(
                            ((dashboard.factors.length - unavailable) /
                              dashboard.factors.length) *
                              100,
                          )
                        : 0
                    }%`,
                  }}
                />
              </div>
              <p className="mt-1.5 text-[11px] text-muted">
                {dashboard.factors.length - unavailable} of {dashboard.factors.length}{" "}
                checks supported
              </p>
            </div>
          </div>
        </div>
      </Panel>

      <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label="Critical & high findings"
          value={openHigh}
          hint={
            openHigh === 0
              ? "No high-severity issues in implemented checks"
              : "Prioritize these first"
          }
          icon={<AlertTriangle className="h-4 w-4" aria-hidden />}
          tone={openHigh > 0 ? "danger" : "ok"}
        />
        <KpiCard
          label="Firewall"
          value={statusWord(firewall?.status)}
          hint={firewall?.evidence || "No firewall evidence available"}
          icon={<Flame className="h-4 w-4" aria-hidden />}
          tone={
            firewall?.status === "pass"
              ? "ok"
              : firewall?.status === "fail"
                ? "danger"
                : "warn"
          }
        />
        <KpiCard
          label="Disk encryption"
          value={statusWord(filevault?.status)}
          hint={filevault?.evidence || "FileVault status unavailable"}
          icon={<Lock className="h-4 w-4" aria-hidden />}
          tone={
            filevault?.status === "pass"
              ? "ok"
              : filevault?.status === "fail"
                ? "danger"
                : "warn"
          }
        />
        <KpiCard
          label="Automatic updates"
          value={statusWord(updates?.status)}
          hint={updates?.evidence || "Update schedule unavailable"}
          icon={<RefreshCw className="h-4 w-4" aria-hidden />}
          tone={
            updates?.status === "pass"
              ? "ok"
              : updates?.status === "warning"
                ? "warn"
                : updates?.status === "fail"
                  ? "danger"
                  : "warn"
          }
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.65fr_1fr]">
        <Panel>
          <PanelHeader
            title="Recommended actions"
            description="Findings are ordered by severity. Each includes evidence and a verification step."
            actions={
              findings.length > 0 ? (
                <span className="chip">{findings.length} open</span>
              ) : undefined
            }
          />
          {findings.length === 0 ? (
            <EmptyState
              icon={<CheckCircle2 className="h-5 w-5 text-ok" aria-hidden />}
              title="No issues reported by implemented checks"
              description="This is not a clean bill of health. Malware scanning, vulnerability matching, and event monitoring are not implemented yet, so they cannot contribute findings."
            />
          ) : (
            <div className="divide-y divide-line/70">
              {findings.map((finding) => (
                <details key={finding.id} className="group px-5 py-4">
                  <summary className="flex cursor-pointer list-none items-start gap-3">
                    <SeverityBadge severity={finding.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-start justify-between gap-3">
                        <p className="text-sm font-semibold text-ink">{finding.title}</p>
                        <ChevronDown
                          className="mt-0.5 h-4 w-4 shrink-0 text-faint transition-transform group-open:rotate-180"
                          aria-hidden
                        />
                      </div>
                      <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">
                        {finding.explanation}
                      </p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-[0.08em] text-faint">
                        <span>{severityLabel(finding.severity)}</span>
                        <span>•</span>
                        <span>{finding.category.replace(/_/g, " ")}</span>
                        <span>•</span>
                        <span>{formatRelative(finding.detectedAt)}</span>
                      </div>
                    </div>
                  </summary>
                  <div className="mt-4 ml-[70px] space-y-3 border-l border-line pl-4">
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-faint">
                        Evidence
                      </p>
                      <p className="mono mt-1 break-words text-xs text-muted">
                        {finding.evidence}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-faint">
                        Remediation
                      </p>
                      <p className="mt-1 text-xs leading-relaxed text-ink">
                        {finding.remediation}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-faint">
                        How to verify
                      </p>
                      <p className="mt-1 text-xs leading-relaxed text-muted">
                        {finding.verification}
                      </p>
                    </div>
                    <p className="text-[10px] text-faint">Source: {finding.source}</p>
                  </div>
                </details>
              ))}
            </div>
          )}
        </Panel>

        <div className="space-y-5">
          <Panel>
            <PanelHeader title="Device snapshot" />
            <div className="px-5 py-3">
              <InfoRow label="Host" value={dashboard.system.hostname} />
              <InfoRow
                label="Operating system"
                value={`${dashboard.system.osName} ${dashboard.system.osVersion}`}
              />
              <InfoRow label="Architecture" value={dashboard.system.architecture} mono />
              <InfoRow label="Kernel" value={dashboard.system.kernelVersion} mono />
              <InfoRow
                label="Processor"
                value={`${dashboard.system.cpuBrand} · ${dashboard.system.cpuCores} cores`}
              />
              <InfoRow label="Memory" value={`${dashboard.system.memoryTotalMb} MB`} />
              <InfoRow label="Uptime" value={formatUptime(dashboard.system.uptimeSeconds)} />
            </div>
          </Panel>

          <Panel>
            <PanelHeader title="Scan coverage" />
            <div className="space-y-2 p-4">
              <div className="flex items-center justify-between rounded-lg bg-surface-2 px-3 py-2 text-xs">
                <span className="flex items-center gap-2 text-muted">
                  <ShieldCheck className="h-4 w-4 text-ok" aria-hidden />
                  Posture audit
                </span>
                <span className="font-medium text-ok">Active</span>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-surface-2 px-3 py-2 text-xs">
                <span className="flex items-center gap-2 text-muted">
                  <Activity className="h-4 w-4 text-warn" aria-hidden />
                  Malware scanning
                </span>
                <span className="font-medium text-warn">Not implemented</span>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-surface-2 px-3 py-2 text-xs">
                <span className="flex items-center gap-2 text-muted">
                  <Cpu className="h-4 w-4 text-warn" aria-hidden />
                  Event monitoring
                </span>
                <span className="font-medium text-warn">Not implemented</span>
              </div>
              <div className="flex items-center justify-between rounded-lg bg-surface-2 px-3 py-2 text-xs">
                <span className="flex items-center gap-2 text-muted">
                  <HardDrive className="h-4 w-4 text-warn" aria-hidden />
                  Vulnerability feed
                </span>
                <span className="font-medium text-warn">Not implemented</span>
              </div>
            </div>
          </Panel>
        </div>
      </div>

      <Panel className="mt-5">
        <PanelHeader
          title="Posture checks"
          description="Every weighted signal behind the score. Expand a check to see why it matters and how to verify it."
          actions={<span className="chip">{dashboard.factors.length} checks</span>}
        />
        <div className="grid gap-px bg-line/60 md:grid-cols-2">
          {dashboard.factors.map((factor) => (
            <details key={factor.id} className="group bg-surface px-5 py-3.5">
              <summary className="flex cursor-pointer list-none items-center gap-3">
                <CheckIcon status={factor.status} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-xs font-semibold text-ink">{factor.title}</p>
                  <p className="truncate text-[11px] text-faint">
                    {factor.evidence || "No evidence available"}
                  </p>
                </div>
                <span className="shrink-0 text-[10px] text-faint">
                  {factor.earned}/{factor.weight}
                </span>
                <ChevronDown
                  className="h-3.5 w-3.5 shrink-0 text-faint transition-transform group-open:rotate-180"
                  aria-hidden
                />
              </summary>
              <div className="mt-2 space-y-2 pl-7 text-[11px] leading-relaxed">
                <p className="text-muted">{factor.explanation}</p>
                {factor.status !== "pass" && factor.remediation ? (
                  <p className="text-ink">
                    <span className="font-semibold">Fix: </span>
                    {factor.remediation}
                  </p>
                ) : null}
                {factor.verification ? (
                  <p className="text-muted">
                    <span className="font-semibold text-faint">Verify: </span>
                    {factor.verification}
                  </p>
                ) : null}
                <p className="text-[10px] text-faint">Source: {factor.source}</p>
              </div>
            </details>
          ))}
        </div>
      </Panel>
    </div>
  );
}
