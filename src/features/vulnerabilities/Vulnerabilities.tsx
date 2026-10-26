import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Database,
  Download,
  PackageSearch,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldQuestion,
} from "lucide-react";
import { api } from "../../lib/api";
import type { AdvisoryReport, AdvisoryUpdate, InstalledApp } from "../../lib/types";
import {
  EmptyState,
  ErrorState,
  KpiCard,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
} from "../../components/ui";
import { formatBytes, formatRelative, titleCase } from "../../lib/format";

function trustLabel(app: InstalledApp): { label: string; tone: string } {
  if (app.source === "Homebrew") return { label: "Homebrew", tone: "text-accent" };
  if (app.source !== "Application") return { label: "Package metadata", tone: "text-muted" };
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
  const [advisory, setAdvisory] = useState<AdvisoryReport | null>(null);
  const [advisoryLoading, setAdvisoryLoading] = useState(true);
  const [advisoryError, setAdvisoryError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);
  const [checking, setChecking] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<AdvisoryUpdate | null>(null);

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

  const loadAdvisory = useCallback(async () => {
    setAdvisoryLoading(true);
    setAdvisoryError(null);
    try {
      setAdvisory(await api.getAdvisoryReport());
    } catch (err) {
      setAdvisoryError(err instanceof Error ? err.message : String(err));
    } finally {
      setAdvisoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    void loadAdvisory();
  }, [load, loadAdvisory]);

  const updateDatabase = useCallback(async () => {
    setUpdating(true);
    setAdvisoryError(null);
    setUpdateInfo(null);
    try {
      const result = await api.updateAdvisoryDatabase();
      setUpdateInfo(result);
      setAdvisory(await api.getAdvisoryReport());
    } catch (err) {
      setAdvisoryError(err instanceof Error ? err.message : String(err));
    } finally {
      setUpdating(false);
      setAdvisoryLoading(false);
    }
  }, []);

  const checkAdvisories = useCallback(async () => {
    setChecking(true);
    setAdvisoryError(null);
    try {
      setAdvisory(await api.getAdvisoryReport());
    } catch (err) {
      setAdvisoryError(err instanceof Error ? err.message : String(err));
    } finally {
      setChecking(false);
    }
  }, []);

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
  const packageApps = apps.filter((app) => app.source !== "Application");
  const packageSources = Array.from(new Set(packageApps.map((app) => app.source))).sort();
  const unsigned = apps.filter(
    (app) => app.source === "Application" && !app.signedBy && app.obtainedFrom !== "apple",
  ).length;

  return (
    <div className="fade-in">
      <PageHeader
        title="Vulnerabilities"
        subtitle="Installed-software inventory and optional Homebrew advisory matching. Coverage is explicit; this is not a complete vulnerability scan."
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
            <strong className="text-ink">Not a complete vulnerability scan.</strong>{" "}
            Inventory alone says nothing about vulnerabilities. Homebrew matching uses a
            downloaded feed with limited coverage; applications are not matched. A result
            is advisory context, and no result is not proof of safety.
          </div>
        </div>
      </div>

      <Panel className="mb-5">
        <PanelHeader
          title="Homebrew advisories"
          description={
            advisory?.available
              ? `${advisory.source} · fetched ${formatRelative(advisory.fetchedAt)}`
              : "Optional local matching against Homebrew's OSV-format advisory database."
          }
          actions={
            <>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => void updateDatabase()}
                disabled={updating || checking}
              >
                <Download className={`h-3.5 w-3.5 ${updating ? "animate-pulse" : ""}`} aria-hidden />
                {updating ? "Updating…" : "Update database"}
              </button>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => void checkAdvisories()}
                disabled={!advisory?.available || updating || checking}
              >
                <ShieldAlert className={`h-3.5 w-3.5 ${checking ? "animate-pulse" : ""}`} aria-hidden />
                {checking ? "Checking…" : "Check packages"}
              </button>
            </>
          }
        />

        <div className="border-b border-line px-5 py-4 text-xs leading-relaxed text-muted">
          <p>
            <strong className="text-ink">Limited coverage.</strong> This feed covers
            Homebrew formula CVEs that Homebrew records as resolved by a patch or version
            bump. Homebrew says automatically generated records use the currently shipped
            version as an approximate boundary, not the exact fixing revision. CyberGates
            now treats those records as unverified; only non-generated records with a
            same-version revision patch can appear as candidate matches. Applications and
            other package managers are not matched.
          </p>
          <p className="mt-2 text-faint">
            Updating downloads about 14 MB from codeload.github.com and sends no device
            data. Matching runs locally against the downloaded database.
          </p>
        </div>

        {advisoryError ? (
          <ErrorState
            message={advisoryError}
            onRetry={() => (advisory?.available ? void checkAdvisories() : void updateDatabase())}
          />
        ) : advisoryLoading && !advisory ? (
          <LoadingState label="Reading advisory database status" />
        ) : !advisory ? (
          <EmptyState
            icon={<Database className="h-5 w-5" aria-hidden />}
            title="Advisory database unavailable"
            description="The local advisory status could not be read."
            action={
              <button type="button" className="btn btn-sm" onClick={() => void loadAdvisory()}>
                Try again
              </button>
            }
          />
        ) : !advisory.available ? (
          <EmptyState
            icon={<Database className="h-5 w-5" aria-hidden />}
            title="Advisory database not downloaded"
            description="Download Homebrew's advisory database to enable local matching. This is optional and requires network access; the rest of the inventory works offline."
            action={
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => void updateDatabase()}
                disabled={updating}
              >
                <Download className="h-3.5 w-3.5" aria-hidden />
                {updating ? "Downloading and indexing…" : "Download advisory database"}
              </button>
            }
          />
        ) : (
          <>
            <div className="grid gap-3 border-b border-line px-5 py-4 sm:grid-cols-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
                  Records
                </p>
                <p className="mt-1 text-lg font-semibold text-ink">{advisory.recordCount}</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
                  Packages indexed
                </p>
                <p className="mt-1 text-lg font-semibold text-ink">{advisory.packageCount}</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
                  Homebrew packages checked
                </p>
                <p className="mt-1 text-lg font-semibold text-ink">{advisory.checkedPackages}</p>
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-faint">
                  Candidate matches
                </p>
                <p className={`mt-1 text-lg font-semibold ${advisory.matches.length > 0 ? "text-warn" : "text-ok"}`}>
                  {advisory.matches.length}
                </p>
              </div>
            </div>

            {updateInfo ? (
              <div className="border-b border-ok/20 bg-ok-soft px-5 py-3 text-xs text-muted">
                Updated to {updateInfo.recordCount} records for {updateInfo.packageCount}{" "}
                packages ({formatBytes(updateInfo.bytes)} downloaded)
                {updateInfo.skippedRecords > 0
                  ? `; ${updateInfo.skippedRecords} unusable records were skipped`
                  : ""}
                .
              </div>
            ) : null}

            {advisory.matches.length === 0 ? (
              <EmptyState
                icon={<CheckCircle2 className="h-5 w-5" aria-hidden />}
                title="No reviewed revision-patch matches found"
                description="No installed Homebrew package matched a non-generated same-version patch boundary. This is not proof of safety: generated records and version-bump records are not evaluated, the feed is incomplete, and application versions are not matched."
              />
            ) : (
              <>
                <div className="border-b border-warn/20 bg-warn-soft px-5 py-3 text-xs leading-relaxed text-muted">
                  <strong className="text-ink">
                    Candidate matches, not confirmed vulnerabilities.
                  </strong>{" "}
                These are installed revisions below a reviewed patch boundary. Verify the
                advisory and the affected range before acting.
                </div>
                <div className="max-h-[520px] overflow-auto">
                <table className="table">
                  <thead className="sticky top-0 z-10 bg-surface">
                    <tr>
                      <th>Package</th>
                      <th>Installed</th>
                      <th>Advisory</th>
                      <th>Summary</th>
                      <th>Patch at</th>
                      <th>Severity</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {advisory.matches.map((item) => (
                      <tr key={`${item.package}-${item.id}`}>
                        <td className="font-medium">{item.package}</td>
                        <td className="mono text-xs text-muted">{item.installedVersion}</td>
                        <td>
                          <p className="mono text-[11px] text-ink">{item.id}</p>
                          {item.aliases.length > 0 ? (
                            <p className="mt-0.5 text-[10px] text-faint">
                              {item.aliases.join(", ")}
                            </p>
                          ) : null}
                          {item.modified ? (
                            <p className="mt-0.5 text-[10px] text-faint">
                              modified {item.modified.slice(0, 10)}
                            </p>
                          ) : null}
                        </td>
                        <td className="max-w-[24rem] text-xs text-muted">
                          <span title={item.summary}>{item.summary}</span>
                        </td>
                        <td className="mono text-xs text-muted">
                          {item.fixed ?? "open-ended"}
                        </td>
                        <td>
                          {item.severity ? (
                            <span
                              className="chip mono max-w-[10rem] truncate"
                              title={item.severity}
                            >
                              CVSS
                            </span>
                          ) : (
                            <span className="text-xs text-faint">—</span>
                          )}
                        </td>
                        <td className="max-w-[18rem] truncate text-[10px] text-faint">
                          {item.references[0] ? (
                            <span className="mono" title={item.references[0]}>
                              {item.references[0]}
                            </span>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
              </>
            )}

            {advisory.unverifiedRecords > 0 ? (
              <p className="border-t border-line px-5 py-3 text-xs text-muted">
                {advisory.unverifiedRecords} advisory record
                {advisory.unverifiedRecords === 1 ? "" : "s"} mention installed packages
                but were not evaluated because the feed does not provide a reviewed fixed
                boundary (including automatically generated boundaries and version bumps).
                They are not counted as matches.
              </p>
            ) : null}
            {advisory.uncomparedPackages.length > 0 ? (
              <p className="border-t border-line px-5 py-3 text-xs text-warn">
                Could not compare versions for: {advisory.uncomparedPackages.join(", ")}. No
                claim is made for these packages.
              </p>
            ) : null}
            {advisory.skippedPackages.length > 0 ? (
              <p className="border-t border-line px-5 py-3 text-xs text-muted">
                Skipped: {advisory.skippedPackages.join("; ")}.
              </p>
            ) : null}
          </>
        )}
      </Panel>

      <div className="mb-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label="Items inventoried"
          value={apps.length}
          hint="Read-only native software inventory"
          icon={<Boxes className="h-4 w-4" aria-hidden />}
          tone="accent"
        />
        <KpiCard
          label="Application records"
          value={applicationCount}
          hint="App metadata provided by the operating system"
          icon={<PackageSearch className="h-4 w-4" aria-hidden />}
          tone="neutral"
        />
        <KpiCard
          label="Package records"
          value={packageApps.length}
          hint={packageSources.length === 0 ? "No package manager reported" : packageSources.join(", ")}
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
                ? "The native inventory provider returned nothing. On macOS, system_profiler may have failed; on Linux, no supported package database may be available."
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
              Homebrew matching is limited to the downloaded Homebrew advisory feed and
              only runs when you request it. Applications are not matched yet, and
              CyberGates will not guess from package names or loose version strings.
            </p>
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="Coverage and limits" />
          <div className="space-y-2 p-5 text-xs leading-relaxed text-muted">
            <p>
              macOS applications come from <span className="mono">system_profiler</span> and
              Homebrew formulae from <span className="mono">brew list --versions</span>.
              Linux package records come from the detected dpkg, RPM, or pacman database.
              These package records include names and versions only; they are not matched
              against Linux vulnerability advisories.
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
