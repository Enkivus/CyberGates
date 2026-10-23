import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Download,
  FileJson,
  FileText,
  History,
  ListChecks,
} from "lucide-react";
import { api } from "../../lib/api";
import type {
  AuditLogEntry,
  AuditRecord,
  Finding,
  ReportExport,
} from "../../lib/types";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  Panel,
  PanelHeader,
  SeverityBadge,
} from "../../components/ui";
import {
  formatBytes,
  formatDateTime,
  formatRelative,
  titleCase,
} from "../../lib/format";

export function Reports() {
  const [audits, setAudits] = useState<AuditRecord[]>([]);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [selectedAudit, setSelectedAudit] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<string | null>(null);
  const [exported, setExported] = useState<ReportExport | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [history, log] = await Promise.all([
        api.getAuditHistory(100),
        api.getAuditLog(100),
      ]);
      setAudits(history);
      setLogs(log);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const viewFindings = async (auditId: string) => {
    setSelectedAudit(auditId);
    setFindings(null);
    try {
      setFindings(await api.getAuditFindings(auditId));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const exportReport = async (auditId: string, format: "json" | "html") => {
    setExporting(`${auditId}-${format}`);
    setError(null);
    try {
      const result = await api.exportReport(auditId, format);
      setExported(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="fade-in">
      <PageHeader
        title="Reports and History"
        subtitle="Persistent audit history, sanitized exports, and a privileged-action audit trail. Reports are generated locally."
        actions={
          <button type="button" className="btn" onClick={() => void load()} disabled={loading}>
            <History className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
        }
      />

      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}

      {exported ? (
        <div className="mb-5 rounded-xl border border-ok/30 bg-ok-soft p-4">
          <div className="flex items-start gap-3">
            <Download className="mt-0.5 h-4 w-4 shrink-0 text-ok" aria-hidden />
            <div className="min-w-0">
              <p className="text-xs font-semibold text-ink">
                {exported.format.toUpperCase()} report written ({formatBytes(exported.bytes)})
              </p>
              <p className="mono mt-1 break-all text-[11px] text-muted">{exported.path}</p>
              <p className="mt-1.5 text-[11px] leading-relaxed text-warn">
                <AlertTriangle className="mr-1 inline h-3 w-3" aria-hidden />
                {exported.warning}
              </p>
            </div>
          </div>
        </div>
      ) : null}

      <Panel className="mb-5">
        <PanelHeader
          title="Audit history"
          description="Each audit stores its weighted checks and findings. History is pruned according to the retention setting."
          actions={<span className="chip">{audits.length} audits</span>}
        />
        {loading && audits.length === 0 ? (
          <LoadingState label="Loading audit history" />
        ) : audits.length === 0 ? (
          <EmptyState
            icon={<ListChecks className="h-5 w-5" aria-hidden />}
            title="No audits yet"
            description="Run the posture audit from Overview to create the first persisted result."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Platform</th>
                  <th>Score</th>
                  <th>Findings</th>
                  <th>Status</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {audits.map((audit) => (
                  <tr key={audit.id}>
                    <td>
                      <p className="text-xs font-medium text-ink">
                        {formatDateTime(audit.startedAt)}
                      </p>
                      <p className="text-[10px] text-faint">
                        {formatRelative(audit.startedAt)}
                      </p>
                    </td>
                    <td className="text-xs text-muted">{audit.platform}</td>
                    <td>
                      <span
                        className={`text-sm font-semibold ${
                          audit.score === null
                            ? "text-faint"
                            : audit.score >= 75
                              ? "text-ok"
                              : audit.score >= 50
                                ? "text-warn"
                                : "text-danger"
                        }`}
                      >
                        {audit.score ?? "—"}
                      </span>
                    </td>
                    <td className="text-xs text-muted">{audit.findingsCount}</td>
                    <td>
                      <span className="chip">{titleCase(audit.status)}</span>
                    </td>
                    <td>
                      <div className="flex justify-end gap-1.5">
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void viewFindings(audit.id)}
                        >
                          <ListChecks className="h-3.5 w-3.5" aria-hidden />
                          View
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void exportReport(audit.id, "html")}
                          disabled={exporting !== null}
                        >
                          <FileText className="h-3.5 w-3.5" aria-hidden />
                          HTML
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => void exportReport(audit.id, "json")}
                          disabled={exporting !== null}
                        >
                          <FileJson className="h-3.5 w-3.5" aria-hidden />
                          JSON
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selectedAudit ? (
        <Panel className="mb-5">
          <PanelHeader
            title="Audit findings"
            description="Findings recorded for the selected audit, including resolved entries from earlier reports."
            actions={
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setSelectedAudit(null);
                  setFindings(null);
                }}
              >
                Close
              </button>
            }
          />
          {findings === null ? (
            <LoadingState label="Loading findings" />
          ) : findings.length === 0 ? (
            <EmptyState
              title="No findings in this audit"
              description="The implemented checks reported no warnings or failures."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Category</th>
                    <th>Evidence</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="text-xs font-medium">{finding.title}</td>
                      <td className="text-xs text-muted">{titleCase(finding.category)}</td>
                      <td className="mono max-w-md text-[11px] text-muted">
                        {finding.evidence}
                      </td>
                      <td>
                        <span className="chip">{titleCase(finding.status)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      ) : null}

      <Panel>
        <PanelHeader
          title="Activity log"
          description="Local audit trail of application and configuration events. Secrets and file contents are not logged."
        />
        {logs.length === 0 ? (
          <EmptyState title="No activity recorded" description="Actions will appear here as they occur." />
        ) : (
          <div className="max-h-[420px] overflow-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Detail</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td className="whitespace-nowrap text-xs text-muted">
                      {formatDateTime(log.at)}
                    </td>
                    <td className="mono text-[11px]">{log.action}</td>
                    <td className="text-xs text-muted">{log.detail}</td>
                    <td>
                      <span className="chip">{titleCase(log.outcome)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
