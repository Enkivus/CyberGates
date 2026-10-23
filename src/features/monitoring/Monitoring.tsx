import { useCallback, useEffect, useMemo, useState } from "react";
import { Cpu, MemoryStick, RefreshCw, Search, Terminal } from "lucide-react";
import { api } from "../../lib/api";
import type { ProcessInfo } from "../../lib/types";
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

  useEffect(() => {
    void load();
  }, [load]);

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

  const topCpu = processes[0];
  const totalMemory = processes.reduce((sum, process) => sum + process.memoryMb, 0);

  return (
    <div className="fade-in">
      <PageHeader
        title="System Monitoring"
        subtitle="A live snapshot of running processes read from the operating system. Event monitoring and behavioral detection are not implemented yet."
        actions={
          <button
            type="button"
            className="btn"
            onClick={() => void load()}
            disabled={loading}
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
        or detect behavior yet. Process termination will require explicit confirmation
        when implemented.
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
