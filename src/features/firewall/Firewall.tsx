import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Ban,
  EyeOff,
  ListChecks,
  Lock,
  RefreshCw,
  Search,
  Shield,
} from "lucide-react";
import { api } from "../../lib/api";
import type { FirewallSnapshot } from "../../lib/types";
import {
  EmptyState,
  ErrorState,
  KpiCard,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
} from "../../components/ui";
import { formatRelative } from "../../lib/format";

function stateLabel(value: boolean | null, on = "On", off = "Off"): string {
  if (value === null) return "Unknown";
  return value ? on : off;
}

function actionTone(action: string): string {
  if (action.startsWith("Block")) return "text-ok";
  if (action.startsWith("Allow")) return "text-warn";
  return "text-faint";
}

export function Firewall() {
  const [snapshot, setSnapshot] = useState<FirewallSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [action, setAction] = useState("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setSnapshot(await api.getFirewallSnapshot());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    if (!snapshot) return [];
    const needle = query.trim().toLowerCase();
    return snapshot.rules.filter((rule) => {
      if (action === "allow" && !rule.action.startsWith("Allow")) return false;
      if (action === "block" && !rule.action.startsWith("Block")) return false;
      if (!needle) return true;
      return rule.path.toLowerCase().includes(needle);
    });
  }, [snapshot, query, action]);

  const allowCount = snapshot?.rules.filter((rule) => rule.action.startsWith("Allow")).length ?? 0;
  const blockCount = snapshot?.rules.filter((rule) => rule.action.startsWith("Block")).length ?? 0;

  return (
    <div className="fade-in">
      <PageHeader
        title="Firewall"
        subtitle="Read-only observations of firewall settings and tools available on this platform. CyberGates does not change firewall configuration."
        actions={
          <button type="button" className="btn" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
        }
      />

      <div className="mb-5 rounded-xl border border-accent/30 bg-accent-soft px-4 py-3 text-xs leading-relaxed text-muted">
        <div className="flex items-start gap-3">
          <Lock className="mt-0.5 h-4 w-4 shrink-0 text-accent" aria-hidden />
          <div>
            <strong className="text-ink">Read-only inspection.</strong> Nothing on this page
            modifies the firewall. Tool status can be partial and is not a complete firewall
            policy assessment.
          </div>
        </div>
      </div>

      {error ? (
        <Panel>
          <ErrorState message={error} onRetry={() => void load()} />
        </Panel>
      ) : loading && !snapshot ? (
        <Panel>
          <LoadingState label="Reading firewall state" />
        </Panel>
      ) : !snapshot ? (
        <Panel>
          <EmptyState
            icon={<Shield className="h-5 w-5" aria-hidden />}
            title="Firewall inspection unavailable"
            description="This platform has no read-only firewall adapter yet. No status is inferred."
          />
        </Panel>
      ) : snapshot.backends.length > 0 ? (
        <Panel>
          <PanelHeader
            title="Firewall manager observations"
            description={`${snapshot.source} · read ${formatRelative(snapshot.fetchedAt)}`}
          />
          <div className="space-y-4 p-5">
            <p className="text-xs leading-relaxed text-muted">{snapshot.scopeNote}</p>
            <div className="grid gap-3 md:grid-cols-3">
              {snapshot.backends.map((backend) => (
                <section key={backend.name} className="rounded-xl border border-line bg-surface-2 p-4">
                  <p className="text-xs font-medium text-muted">{backend.name}</p>
                  <p className="mt-1 text-sm font-semibold text-ink">{backend.state}</p>
                  <p className="mt-2 text-xs leading-relaxed text-muted">{backend.detail}</p>
                </section>
              ))}
            </div>
          </div>
        </Panel>
      ) : (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <KpiCard
              label="Firewall"
              value={stateLabel(snapshot.enabled, "Enabled", "Disabled")}
              hint="Global Application Firewall state"
              icon={<Shield className="h-4 w-4" aria-hidden />}
              tone={snapshot.enabled === true ? "ok" : snapshot.enabled === false ? "danger" : "neutral"}
            />
            <KpiCard
              label="Stealth mode"
              value={stateLabel(snapshot.stealthMode, "On", "Off")}
              hint="Probe response behavior"
              icon={<EyeOff className="h-4 w-4" aria-hidden />}
              tone={snapshot.stealthMode === true ? "ok" : "neutral"}
            />
            <KpiCard
              label="Block all"
              value={stateLabel(snapshot.blockAll, "On", "Off")}
              hint="Deny all non-essential incoming traffic"
              icon={<Ban className="h-4 w-4" aria-hidden />}
              tone={snapshot.blockAll === true ? "ok" : "neutral"}
            />
            <KpiCard
              label="Application rules"
              value={snapshot.rules.length}
              hint={`${allowCount} allow · ${blockCount} block`}
              icon={<ListChecks className="h-4 w-4" aria-hidden />}
              tone="accent"
            />
          </div>

          <Panel>
            <PanelHeader
              title="Application exceptions"
              description={`${snapshot.source} · read ${formatRelative(snapshot.fetchedAt)}`}
              actions={
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    className="select w-32 py-1.5 text-xs"
                    value={action}
                    onChange={(event) => setAction(event.target.value)}
                    aria-label="Filter by action"
                  >
                    <option value="all">All actions</option>
                    <option value="allow">Allow</option>
                    <option value="block">Block</option>
                  </select>
                  <div className="relative">
                    <Search
                      className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                      aria-hidden
                    />
                    <input
                      value={query}
                      onChange={(event) => setQuery(event.target.value)}
                      placeholder="Filter application path"
                      className="input w-64 py-1.5 pl-8 text-xs"
                      aria-label="Filter firewall rules"
                    />
                  </div>
                </div>
              }
            />
            {filtered.length === 0 ? (
              <EmptyState
                icon={<ListChecks className="h-5 w-5" aria-hidden />}
                title={snapshot.rules.length === 0 ? "No application exceptions" : "No matches"}
                description={
                  snapshot.rules.length === 0
                    ? "macOS reported no per-application firewall exceptions."
                    : "Adjust the search or action filter."
                }
              />
            ) : (
              <div className="max-h-[560px] overflow-auto">
                <table className="table">
                  <thead className="sticky top-0 z-10 bg-surface">
                    <tr>
                      <th className="w-12">#</th>
                      <th>Application / binary</th>
                      <th className="w-56">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((rule, index) => (
                      <tr key={`${rule.path}-${index}`}>
                        <td className="mono text-[11px] text-faint">{index + 1}</td>
                        <td className="mono max-w-[46rem] break-all text-[11px]">{rule.path}</td>
                        <td>
                          <span className={`text-xs font-medium ${actionTone(rule.action)}`}>
                            {rule.action}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <div className="mt-5 grid gap-5 md:grid-cols-2">
            <Panel>
              <PanelHeader title="Signed software handling" />
              <div className="space-y-3 p-5 text-xs leading-relaxed text-muted">
                <div className="flex items-center justify-between gap-4">
                  <span>Automatically allow built-in signed software</span>
                  <span className="font-medium text-ink">
                    {stateLabel(snapshot.allowSignedBuiltin, "Enabled", "Disabled")}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span>Automatically allow downloaded signed software</span>
                  <span className="font-medium text-ink">
                    {stateLabel(snapshot.allowSignedDownloaded, "Enabled", "Disabled")}
                  </span>
                </div>
              </div>
            </Panel>
            <Panel>
              <PanelHeader title="Interpretation limits" />
              <div className="space-y-2 p-5 text-xs leading-relaxed text-muted">
                <p>{snapshot.scopeNote}</p>
                <p className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />
                  An "Allow" rule is not automatically unsafe, and a "Block" rule is not
                  automatically sufficient. Review the application and its purpose.
                </p>
                <p>
                  Transient helper processes and system services may appear or disappear
                  between refreshes.
                </p>
              </div>
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
