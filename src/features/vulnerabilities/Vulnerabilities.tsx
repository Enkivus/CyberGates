import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Boxes,
  CheckCircle2,
  PackageSearch,
  RefreshCw,
  Search,
  ShieldQuestion,
} from "lucide-react";
import { api } from "../../lib/api";
import type { InstalledApp } from "../../lib/types";
import {
  EmptyState,
  ErrorState,
  KpiCard,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
} from "../../components/ui";
import { formatRelative, titleCase } from "../../lib/format";

function trustLabel(app: InstalledApp): { label: string; tone: string } {
  if (app.source === "Homebrew") return { label: "Homebrew", tone: "text-accent" };
  if (app.obtainedFrom === "apple") return { label: "Apple", tone: "text-ok" };
  if (app.signedBy?.startsWith("Developer ID")) {
    return { label: "Developer ID", tone: "text-ok" };
  }
  if (app.obtainedFrom === "mac_app_store") return { label: "App Store", tone: "text-ok" };
  if (app.signedBy) return { label: "Signed", tone: "text-ok" };
  return { label: "No signature info", tone: "text-warn" };
}

export function Vulnerabilities() {
  const [apps, setApps] = useState<InstalledApp[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("all");
  const [loadedAt, setLoadedAt] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setApps(await api.getInstalledApps());
      setLoadedAt(new Date().toISOString());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const sources = useMemo(
    () => Array.from(new Set(apps.map((app) => app.source))).sort(),
    [apps],
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return apps.filter((app) => {
      if (source !== "all" && app.source !== source) return false;
      if (!needle) return true;
      return [app.name, app.version, app.path, app.signedBy]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [apps, query, source]);

  const applicationCount = apps.filter((app) => app.source === "Application").length;
  const homebrewCount = apps.filter((app) => app.source === "Homebrew").length;
  const unsigned = apps.filter(
    (app) => app.source === "Application" && !app.signedBy && app.obtainedFrom !== "apple",
  ).length;

  return (
    <div className="fade-in">
      <PageHeader
        title="Vulnerabilities"
        subtitle="Installed application and package inventory. Advisory matching is not implemented, so CyberGates makes no claim about whether any item is vulnerable."
        actions={
          <button
            type="button"
            className="btn"
            onClick={() => void load()}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh inventory
          </button>
        }
      />

      <div className="mb-5 rounded-xl border border-warn/30 bg-warn-soft px-4 py-3 text-xs leading-relaxed text-muted">
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />
          <div>
            <strong className="text-ink">Inventory only — not a vulnerability scan.</strong>{" "}
            No advisory feed or version-range matching is connected. This list must not be
            read as "no vulnerabilities". When matching is implemented, every result will
            show its advisory source and data freshness.
          </div>
        </div>
      </div>

      <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label="Items inventoried"
          value={apps.length}
          hint="macOS applications + Homebrew"
          icon={<Boxes className="h-4 w-4" aria-hidden />}
          tone="accent"
        />
        <KpiCard
          label="Applications"
          value={applicationCount}
          hint="Discovered via system_profiler"
          icon={<PackageSearch className="h-4 w-4" aria-hidden />}
          tone="neutral"
        />
        <KpiCard
          label="Homebrew packages"
          value={homebrewCount}
          hint={homebrewCount === 0 ? "Homebrew not detected" : "Formulae listed by brew"}
          icon={<Boxes className="h-4 w-4" aria-hidden />}
          tone="neutral"
        />
        <KpiCard
          label="Apps without signature info"
          value={unsigned}
          hint="Review trust manually; not proof of malware"
          icon={<ShieldQuestion className="h-4 w-4" aria-hidden />}
          tone={unsigned > 0 ? "warn" : "ok"}
        />
      </div>

      <Panel>
        <PanelHeader
          title="Installed software"
          description={
            loadedAt
              ? `Read-only inventory refreshed ${formatRelative(loadedAt)}.`
              : "Read-only inventory from native package sources."
          }
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <select
                className="select w-40 py-1.5 text-xs"
                value={source}
                onChange={(event) => setSource(event.target.value)}
                aria-label="Filter by source"
              >
                <option value="all">All sources</option>
                {sources.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                  aria-hidden
                />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Filter name, version, or path"
                  className="input w-64 py-1.5 pl-8 text-xs"
                  aria-label="Filter installed software"
                />
              </div>
            </div>
          }
        />
        {error ? (
          <ErrorState message={error} onRetry={() => void load()} />
        ) : loading && apps.length === 0 ? (
          <LoadingState label="Reading installed software inventory" />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<PackageSearch className="h-5 w-5" aria-hidden />}
            title={apps.length === 0 ? "No software inventory available" : "No matches"}
            description={
              apps.length === 0
                ? "The native inventory provider returned nothing. On unsupported platforms this module is unavailable; on macOS, system_profiler may have failed."
                : "Adjust the search or source filter."
            }
          />
        ) : (
          <div className="max-h-[620px] overflow-auto">
            <table className="table">
              <thead className="sticky top-0 z-10 bg-surface">
                <tr>
                  <th>Name</th>
                  <th>Version</th>
                  <th>Source</th>
                  <th>Trust / signature</th>
                  <th>Path</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((app, index) => {
                  const trust = trustLabel(app);
                  return (
                    <tr key={`${app.source}-${app.name}-${index}`}>
                      <td className="font-medium">{app.name}</td>
                      <td className="mono text-xs text-muted">{app.version ?? "—"}</td>
                      <td>
                        <span className="chip">{titleCase(app.source)}</span>
                      </td>
                      <td>
                        <span className={`text-xs font-medium ${trust.tone}`}>
                          {trust.label}
                        </span>
                        {app.signedBy ? (
                          <p className="mt-0.5 max-w-[22rem] truncate text-[10px] text-faint">
                            {app.signedBy}
                          </p>
                        ) : null}
                      </td>
                      <td className="mono max-w-[26rem] truncate text-[11px] text-faint">
                        {app.path ?? (app.source === "Homebrew" ? "Managed by brew" : "—")}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="mt-5 grid gap-5 md:grid-cols-2">
        <Panel>
          <PanelHeader title="What this list does not mean" />
          <div className="space-y-2 p-5 text-xs leading-relaxed text-muted">
            <p className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-muted" aria-hidden />
              Presence in this list is <strong className="text-ink">not</strong> a
              vulnerability finding and absence is not proof of safety.
            </p>
            <p>
              CyberGates does not yet know which versions are affected by which advisories.
              It will not guess from package names or loose version strings.
            </p>
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="Coverage and limits" />
          <div className="space-y-2 p-5 text-xs leading-relaxed text-muted">
            <p>
              macOS applications come from <span className="mono">system_profiler</span>;
              Homebrew formulae come from <span className="mono">brew list --versions</span>.
              Other package managers and per-user app locations are not covered yet.
            </p>
            <p>
              Signature information is displayed as reported by macOS. It is a trust
              signal, not a malware verdict.
            </p>
          </div>
        </Panel>
      </div>
    </div>
  );
}
