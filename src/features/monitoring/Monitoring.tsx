import { useCallback, useEffect, useMemo, useState } from "react";
import { Cpu, MemoryStick, RefreshCw, Search, Terminal } from "lucide-react";
import { api } from "../../lib/api";
import type { LoadedServiceInventory, ProcessInfo, StartupInventory } from "../../lib/types";
import {
  EmptyState,
  ErrorState,
  KpiCard,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
} from "../../components/ui";

function formatRuntime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function Monitoring() {
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<ProcessInfo | null>(null);
  const [startupInventory, setStartupInventory] = useState<StartupInventory | null>(null);
  const [startupLoading, setStartupLoading] = useState(true);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [startupQuery, setStartupQuery] = useState("");
  const [services, setServices] = useState<LoadedServiceInventory | null>(null);
  const [servicesLoading, setServicesLoading] = useState(true);
  const [servicesError, setServicesError] = useState<string | null>(null);
  const [servicesQuery, setServicesQuery] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setProcesses(await api.getProcesses(400));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadStartup = useCallback(async () => {
    setStartupLoading(true);
    setStartupError(null);
    try {
      setStartupInventory(await api.getStartupInventory());
    } catch (err) {
      setStartupError(err instanceof Error ? err.message : String(err));
    } finally {
      setStartupLoading(false);
    }
  }, []);

  const loadServices = useCallback(async () => {
    setServicesLoading(true);
    setServicesError(null);
    try {
      setServices(await api.getLoadedServices());
    } catch (err) {
      setServicesError(err instanceof Error ? err.message : String(err));
    } finally {
      setServicesLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    void loadStartup();
    void loadServices();
  }, [load, loadStartup, loadServices]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return processes;
    return processes.filter(
      (process) =>
        process.name.toLowerCase().includes(needle) ||
        String(process.pid).includes(needle) ||
        (process.executable ?? "").toLowerCase().includes(needle),
    );
  }, [processes, query]);

  const filteredStartupItems = useMemo(() => {
    const needle = startupQuery.trim().toLowerCase();
    const items = startupInventory?.items ?? [];
    if (!needle) return items;
    return items.filter((item) =>
      `${item.name} ${item.path} ${item.scope}`.toLowerCase().includes(needle),
    );
  }, [startupInventory, startupQuery]);

  const filteredServices = useMemo(() => {
    const needle = servicesQuery.trim().toLowerCase();
    const items = services?.services ?? [];
    if (!needle) return items;
    return items.filter((service) =>
      `${service.label} ${service.pid ?? ""} ${service.lastExitStatus ?? ""}`
        .toLowerCase()
        .includes(needle),
    );
  }, [services, servicesQuery]);

  const topCpu = processes[0];
  const totalMemory = processes.reduce((sum, process) => sum + process.memoryMb, 0);

  return (
    <div className="fade-in">
      <PageHeader
        title="System Monitoring"
        subtitle="Read-only process and startup-file inventories from the operating system. Event monitoring and behavioral detection are not implemented yet."
        actions={
          <button
            type="button"
            className="btn"
            onClick={() => {
              void load();
              void loadStartup();
              void loadServices();
            }}
            disabled={loading || startupLoading || servicesLoading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
        }
      />

      <div className="mb-5 grid gap-4 sm:grid-cols-3">
        <KpiCard
          label="Processes sampled"
          value={processes.length}
          hint="Top 400 by CPU usage"
          icon={<Terminal className="h-4 w-4" aria-hidden />}
          tone="accent"
        />
        <KpiCard
          label="Top CPU consumer"
          value={topCpu ? topCpu.name : "—"}
          hint={topCpu ? `${topCpu.cpuPercent.toFixed(1)}% CPU` : undefined}
          icon={<Cpu className="h-4 w-4" aria-hidden />}
          tone="warn"
        />
        <KpiCard
          label="Sampled memory"
          value={`${(totalMemory / 1024).toFixed(2)} GB`}
          hint="Sum across sampled processes"
          icon={<MemoryStick className="h-4 w-4" aria-hidden />}
          tone="neutral"
        />
      </div>

      <div className="mb-4 rounded-xl border border-warn/30 bg-warn-soft px-4 py-3 text-xs leading-relaxed text-muted">
        <strong className="text-ink">Scope:</strong> CyberGates lists processes and
        executable paths only. It does not monitor security events, terminate processes,
        or detect behavior yet. Startup files and loaded services are separate read-only
        inventories; only the current user's launchd domain is included.
      </div>

      <Panel>
        <PanelHeader
          title="Running processes"
          description="CPU values are sampled at refresh time and may differ from Activity Monitor."
          actions={
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                aria-hidden
              />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter by name, PID, or path"
                className="input w-64 py-1.5 pl-8 text-xs"
                aria-label="Filter processes"
              />
            </div>
          }
        />
        {error ? (
          <ErrorState message={error} onRetry={() => void load()} />
        ) : loading && processes.length === 0 ? (
          <LoadingState label="Loading processes" />
        ) : filtered.length === 0 ? (
          <EmptyState
            title="No matching processes"
            description="Try a different filter. If the list is empty, the platform process provider may be unavailable."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>Process</th>
                  <th className="text-right">CPU</th>
                  <th className="text-right">Memory</th>
                  <th>Uptime</th>
                  <th>Executable</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((process) => (
                  <tr
                    key={process.pid}
                    className="cursor-pointer"
                    onClick={() => setSelected(process)}
                  >
                    <td className="mono text-xs text-faint">{process.pid}</td>
                    <td className="font-medium">{process.name}</td>
                    <td className="text-right">
                      <span
                        className={
                          process.cpuPercent >= 20
                            ? "text-warn"
                            : process.cpuPercent >= 5
                              ? "text-ink"
                              : "text-muted"
                        }
                      >
                        {process.cpuPercent.toFixed(1)}%
                      </span>
                    </td>
                    <td className="text-right text-muted">
                      {process.memoryMb < 1
                        ? "<1 MB"
                        : `${process.memoryMb.toFixed(0)} MB`}
                    </td>
                    <td className="text-xs text-muted">
                      {formatRuntime(process.runTimeSeconds)}
                    </td>
                    <td className="mono max-w-[26rem] truncate text-[11px] text-faint">
                      {process.executable ?? "Unavailable"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel className="mt-5">
        <PanelHeader
          title="Startup items"
          description={startupInventory?.source ?? "Read-only startup configuration inventory"}
          actions={
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                aria-hidden
              />
              <input
                value={startupQuery}
                onChange={(event) => setStartupQuery(event.target.value)}
                placeholder="Filter startup files"
                className="input w-56 py-1.5 pl-8 text-xs"
                aria-label="Filter startup items"
              />
            </div>
          }
        />
        {startupError ? (
          <ErrorState message={startupError} onRetry={() => void loadStartup()} />
        ) : startupLoading && !startupInventory ? (
          <LoadingState label="Loading startup items" />
        ) : startupInventory && !startupInventory.available ? (
          <EmptyState
            title="Startup inventory unavailable"
            description={startupInventory.scopeNote}
          />
        ) : startupInventory ? (
          <>
            <p className="border-b border-line px-5 py-3 text-xs leading-relaxed text-muted">
              {startupInventory.scopeNote}
            </p>
            {startupInventory.warnings.map((warning) => (
              <p key={warning} className="border-b border-line px-5 py-2 text-xs text-warn">
                {warning}
              </p>
            ))}
            {filteredStartupItems.length === 0 ? (
              <EmptyState
                title={startupInventory.items.length ? "No matching startup files" : "No startup files found"}
                description={startupInventory.items.length ? "Try another filter." : "No regular property-list files were found in the inspected launchd directories."}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th>File name</th>
                      <th>Scope</th>
                      <th>Modified</th>
                      <th>Property-list file</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredStartupItems.map((item) => (
                      <tr key={item.path}>
                        <td className="font-medium">{item.name}</td>
                        <td className="text-xs text-muted">{item.scope}</td>
                        <td className="text-xs text-muted">
                          {item.modifiedAt ? new Date(item.modifiedAt).toLocaleString() : "Unavailable"}
                        </td>
                        <td className="mono max-w-[34rem] break-all text-[11px] text-faint">
                          {item.path}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="border-t border-line px-5 py-2 text-[10px] text-faint">
              {startupInventory.items.length} files listed · refreshed {new Date(startupInventory.fetchedAt).toLocaleTimeString()}
            </p>
          </>
        ) : null}
      </Panel>

      <Panel className="mt-5">
        <PanelHeader
          title="Loaded user services"
          description={services?.source ?? "Read-only launch service state"}
          actions={
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                aria-hidden
              />
              <input
                value={servicesQuery}
                onChange={(event) => setServicesQuery(event.target.value)}
                placeholder="Filter service labels"
                className="input w-56 py-1.5 pl-8 text-xs"
                aria-label="Filter loaded services"
              />
            </div>
          }
        />
        {servicesError ? (
          <ErrorState message={servicesError} onRetry={() => void loadServices()} />
        ) : servicesLoading && !services ? (
          <LoadingState label="Loading loaded services" />
        ) : services && !services.available ? (
          <EmptyState title="Loaded service state unavailable" description={services.scopeNote} />
        ) : services ? (
          <>
            <p className="border-b border-line px-5 py-3 text-xs leading-relaxed text-muted">
              {services.scopeNote}
            </p>
            {filteredServices.length === 0 ? (
              <EmptyState
                title={services.services.length ? "No matching services" : "No loaded services returned"}
                description={services.services.length ? "Try another filter." : "The current-user service provider returned an empty list."}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr><th>Service label</th><th>State</th><th>PID</th><th>Last exit status</th></tr>
                  </thead>
                  <tbody>
                    {filteredServices.map((service) => (
                      <tr key={service.label}>
                        <td className="font-medium">{service.label}</td>
                        <td>
                          <span className={`chip ${service.pid === null ? "" : "status-pass border-transparent"}`}>
                            {service.pid === null ? "Registered, idle" : "Running"}
                          </span>
                        </td>
                        <td className="mono text-xs text-faint">{service.pid ?? "—"}</td>
                        <td className="mono text-xs text-muted">{service.lastExitStatus ?? "Unknown"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="border-t border-line px-5 py-2 text-[10px] text-faint">
              {services.services.length} jobs returned · refreshed {new Date(services.fetchedAt).toLocaleTimeString()}
            </p>
          </>
        ) : null}
      </Panel>

      {selected ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--modal)] p-6"
          role="dialog"
          aria-modal="true"
          aria-label={`Process ${selected.name}`}
          onClick={() => setSelected(null)}
        >
          <div
            className="panel w-full max-w-lg p-5"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-[10px] uppercase tracking-[0.12em] text-faint">
                  Process detail
                </p>
                <h3 className="mt-1 text-lg font-semibold text-ink">{selected.name}</h3>
                <p className="mono text-xs text-muted">PID {selected.pid}</p>
              </div>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setSelected(null)}
              >
                Close
              </button>
            </div>
            <dl className="mt-4 space-y-2 text-xs">
              <div className="flex justify-between gap-4 border-b border-line py-1.5">
                <dt className="text-muted">CPU</dt>
                <dd>{selected.cpuPercent.toFixed(1)}%</dd>
              </div>
              <div className="flex justify-between gap-4 border-b border-line py-1.5">
                <dt className="text-muted">Memory</dt>
                <dd>{selected.memoryMb.toFixed(1)} MB</dd>
              </div>
              <div className="flex justify-between gap-4 border-b border-line py-1.5">
                <dt className="text-muted">Running for</dt>
                <dd>{formatRuntime(selected.runTimeSeconds)}</dd>
              </div>
              <div className="border-b border-line py-1.5">
                <dt className="text-muted">Executable</dt>
                <dd className="mono mt-1 break-all text-[11px]">
                  {selected.executable ?? "Not exposed by the operating system"}
                </dd>
              </div>
            </dl>
            <p className="mt-4 text-[11px] leading-relaxed text-faint">
              Process actions are intentionally not available. CyberGates requires a
              verified response workflow with confirmation and audit logging before it
              will terminate a process.
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}
