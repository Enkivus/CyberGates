import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileText, RefreshCw, Search } from "lucide-react";
import { EmptyState, ErrorState, Panel, PanelHeader } from "../../components/ui";
import { api } from "../../lib/api";
import { formatRelative } from "../../lib/format";

function lineTone(line: string): string {
  if (/\b(ERROR|FATAL)\b/i.test(line)) return "text-danger";
  if (/\bWARN(?:ING)?\b/i.test(line)) return "text-warn";
  return "text-muted";
}

export function ApplicationLogs() {
  const [lines, setLines] = useState<string[]>([]);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [available, setAvailable] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getApplicationLogs();
      setLines(result.lines);
      setWarnings(result.warnings);
      setAvailable(result.available);
      setFetchedAt(result.fetchedAt);
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
    return needle ? lines.filter((line) => line.toLowerCase().includes(needle)) : lines;
  }, [lines, query]);

  return (
    <Panel>
      <PanelHeader
        title="CyberGates application logs"
        description={
          fetchedAt
            ? `Recent local diagnostics · refreshed ${formatRelative(fetchedAt)}`
            : "Recent local application diagnostics"
        }
        actions={
          <button type="button" className="btn btn-sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
        }
      />
      <div className="border-b border-line px-5 py-3 text-xs leading-relaxed text-muted">
        These are CyberGates’ own diagnostics, not operating-system security events. Logs
        stay on this device and may include local paths or error details; review them
        before sharing.
      </div>
      {warnings.length > 0 ? (
        <div className="border-b border-warn/20 bg-warn-soft px-5 py-3 text-xs text-muted">
          <p className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />
            <span>{warnings.join(" ")}</span>
          </p>
        </div>
      ) : null}
      {error ? (
        <div className="p-5">
          <ErrorState message={error} onRetry={() => void load()} />
        </div>
      ) : !available ? (
        <div className="p-5">
          <EmptyState
            icon={<FileText className="h-5 w-5" aria-hidden />}
            title="Application logs unavailable"
            description="CyberGates could not read its private application log directory."
          />
        </div>
      ) : loading && lines.length === 0 ? (
        <div className="p-5 text-xs text-muted" role="status">Loading application logs…</div>
      ) : lines.length === 0 ? (
        <div className="p-5">
          <EmptyState
            icon={<FileText className="h-5 w-5" aria-hidden />}
            title="No application logs yet"
            description="Diagnostics will appear here after CyberGates writes its first log entry."
          />
        </div>
      ) : (
        <>
          <div className="border-b border-line px-5 py-3">
            <div className="relative max-w-md">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint"
                aria-hidden
              />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter log text"
                className="input w-full py-1.5 pl-8 text-xs"
                aria-label="Filter application logs"
              />
            </div>
          </div>
          {filtered.length === 0 ? (
            <div className="p-5 text-xs text-muted">No log lines match that filter.</div>
          ) : (
            <ol className="max-h-[420px] divide-y divide-line overflow-auto" aria-label="Recent application log lines">
              {filtered.map((line, index) => (
                <li key={`${index}-${line.slice(0, 48)}`} className="px-5 py-2.5">
                  <pre className={`whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed ${lineTone(line)}`}>
                    {line}
                  </pre>
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </Panel>
  );
}
