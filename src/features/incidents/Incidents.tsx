import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, FileJson, FileText, Plus, RefreshCw, Send } from "lucide-react";
import { EmptyState, ErrorState, LoadingState, PageHeader, Panel, PanelHeader, SeverityBadge } from "../../components/ui";
import { api } from "../../lib/api";
import type { Finding, IncidentDetail, IncidentExport, IncidentRecord, IncidentStatus } from "../../lib/types";
import { formatBytes, formatDateTime, formatRelative, titleCase } from "../../lib/format";

export function Incidents() {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [openFindings, setOpenFindings] = useState<Finding[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [findingId, setFindingId] = useState("");
  const [note, setNote] = useState("");
  const [statusNote, setStatusNote] = useState("");
  const [nextStatus, setNextStatus] = useState<IncidentStatus>("investigating");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exported, setExported] = useState<IncidentExport | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [items, findings] = await Promise.all([api.getIncidents(), api.getOpenFindings()]);
      setIncidents(items);
      setOpenFindings(findings);
      if (selectedId && items.some((item) => item.id === selectedId)) {
        setDetail(await api.getIncident(selectedId));
      } else if (items.length > 0) {
        setSelectedId(items[0].id);
        setDetail(await api.getIncident(items[0].id));
      } else {
        setSelectedId(null);
        setDetail(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [selectedId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function refreshDetail(id: string) {
    setSelectedId(id);
    setDetail(null);
    setExported(null);
    try {
      setDetail(await api.getIncident(id));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function createFromFinding() {
    if (!findingId || busy) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.createIncident(findingId);
      setSelectedId(created.id);
      setDetail(await api.getIncident(created.id));
      setFindingId("");
      const [items, findings] = await Promise.all([api.getIncidents(), api.getOpenFindings()]);
      setIncidents(items);
      setOpenFindings(findings);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function addNote() {
    if (!detail || note.trim().length < 3 || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.addIncidentNote(detail.incident.id, note);
      setNote("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function changeStatus() {
    if (!detail || statusNote.trim().length < 10 || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.setIncidentStatus(detail.incident.id, nextStatus, statusNote);
      setStatusNote("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function exportReport(format: "json" | "html") {
    if (!detail || exporting) return;
    setExporting(true);
    setError(null);
    setExported(null);
    try {
      setExported(await api.exportIncidentReport(detail.incident.id, format));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="fade-in">
      <PageHeader
        title="Incident Response"
        subtitle="Create local cases from real audit findings and keep a user-entered investigation timeline."
        actions={
          <button type="button" className="btn" onClick={() => void load()} disabled={loading || busy}>
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden />
            Refresh
          </button>
        }
      />

      <div className="mb-5 rounded-xl border border-warn/30 bg-warn-soft px-4 py-3 text-xs leading-relaxed text-muted">
        <AlertTriangle className="mr-2 inline h-4 w-4 text-warn" aria-hidden />
        Cases are local records linked to audit findings. Timeline notes are user-entered; closing a case is an operator decision and does not verify remediation. CyberGates does not isolate networks, stop processes, or change system settings from this page.
      </div>

      {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}

      {exported ? (
        <div className="mb-5 rounded-xl border border-ok/30 bg-ok-soft p-4">
          <p className="text-xs font-semibold text-ink">
            {exported.format.toUpperCase()} incident report written ({formatBytes(exported.bytes)})
          </p>
          <p className="mono mt-1 break-all text-[11px] text-muted">{exported.path}</p>
          <p className="mt-2 text-[11px] leading-relaxed text-warn">{exported.warning}</p>
        </div>
      ) : null}

      <Panel className="mb-5">
        <PanelHeader title="Create a case" description="Start from an open, evidence-backed posture finding." />
        <div className="flex flex-wrap items-center gap-3 p-5">
          <select
            className="select min-w-72 flex-1"
            value={findingId}
            onChange={(event) => setFindingId(event.target.value)}
            aria-label="Choose an open finding"
          >
            <option value="">Select an open finding</option>
            {openFindings.map((finding) => (
              <option value={finding.id} key={finding.id}>
                {finding.title} · {finding.severity.toUpperCase()}
              </option>
            ))}
          </select>
          <button type="button" className="btn btn-primary" disabled={!findingId || busy} onClick={() => void createFromFinding()}>
            <Plus className="h-4 w-4" aria-hidden />
            Create incident
          </button>
          {openFindings.length === 0 ? <p className="text-xs text-muted">There are no open posture findings to attach.</p> : null}
        </div>
      </Panel>

      {loading && incidents.length === 0 ? (
        <LoadingState label="Loading incident records" />
      ) : incidents.length === 0 ? (
        <EmptyState title="No incident cases yet" description="Create a case from an open finding above. Incident records stay on this device." />
      ) : (
        <div className="grid gap-5 xl:grid-cols-[minmax(16rem,0.8fr)_minmax(0,2fr)]">
          <Panel>
            <PanelHeader title="Cases" actions={<span className="chip">{incidents.length}</span>} />
            <div className="divide-y divide-line">
              {incidents.map((incident) => (
                <button
                  type="button"
                  key={incident.id}
                  onClick={() => void refreshDetail(incident.id)}
                  className={`block w-full px-5 py-4 text-left transition-colors hover:bg-surface-2 ${selectedId === incident.id ? "bg-surface-2" : ""}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-sm font-medium text-ink">{incident.title}</span>
                    <SeverityBadge severity={incident.severity} />
                  </div>
                  <div className="mt-2 flex items-center justify-between gap-3 text-[10px] text-muted">
                    <span>{titleCase(incident.status)} · {incident.evidenceCount} evidence</span>
                    <span>{formatRelative(incident.updatedAt)}</span>
                  </div>
                </button>
              ))}
            </div>
          </Panel>

          <Panel>
            <PanelHeader
              title={detail?.incident.title ?? "Case details"}
              description={detail ? `Created ${formatDateTime(detail.incident.createdAt)} · ${detail.incident.status}` : "Choose a case to view its evidence and timeline."}
              actions={detail ? (
                <div className="flex gap-2">
                  <button type="button" className="btn btn-sm" disabled={exporting} onClick={() => void exportReport("html")}>
                    <FileText className="h-3.5 w-3.5" aria-hidden /> HTML
                  </button>
                  <button type="button" className="btn btn-sm" disabled={exporting} onClick={() => void exportReport("json")}>
                    <FileJson className="h-3.5 w-3.5" aria-hidden /> JSON
                  </button>
                </div>
              ) : null}
            />
            {!detail ? (
              <LoadingState label="Loading case details" />
            ) : (
              <div className="divide-y divide-line">
                <section className="p-5">
                  <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Linked audit evidence</h3>
                  {detail.findings.length === 0 ? (
                    <p className="text-sm text-muted">The source finding is no longer retained. Incident notes remain available.</p>
                  ) : detail.findings.map((finding) => (
                    <div className="rounded-xl border border-line p-4" key={finding.id}>
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} />
                        <span className="text-sm font-medium">{finding.title}</span>
                      </div>
                      <p className="mt-2 text-xs leading-relaxed text-muted">{finding.explanation}</p>
                      <p className="mono mt-2 break-all text-[11px] text-faint">{finding.evidence}</p>
                    </div>
                  ))}
                </section>

                <section className="p-5">
                  <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Investigation timeline</h3>
                  <ol className="space-y-3">
                    {detail.events.map((event) => (
                      <li className="border-l-2 border-line pl-3" key={event.id}>
                        <p className="text-[10px] text-faint">{formatDateTime(event.at)} · {titleCase(event.eventType)}</p>
                        <p className="mt-1 whitespace-pre-wrap text-xs leading-relaxed text-ink">{event.detail}</p>
                      </li>
                    ))}
                  </ol>
                </section>

                {detail.incident.status !== "closed" ? (
                  <section className="p-5">
                    <label className="label" htmlFor="incident-note">Add a timeline note</label>
                    <textarea id="incident-note" className="input mt-2 min-h-20 w-full resize-y" maxLength={2000} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Record an observation or investigation step…" />
                    <div className="mt-2 flex justify-end">
                      <button type="button" className="btn btn-sm" disabled={note.trim().length < 3 || busy} onClick={() => void addNote()}>
                        <Send className="h-3.5 w-3.5" aria-hidden /> Add note
                      </button>
                    </div>
                  </section>
                ) : null}

                <section className="p-5">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Case status</h3>
                  <div className="mt-3 grid gap-2 sm:grid-cols-[12rem_minmax(0,1fr)_auto]">
                    <select className="select" value={nextStatus} onChange={(event) => setNextStatus(event.target.value as IncidentStatus)} aria-label="New incident status">
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="closed">Closed by user</option>
                    </select>
                    <input className="input" maxLength={2000} value={statusNote} onChange={(event) => setStatusNote(event.target.value)} placeholder="Explain this status change (10+ characters)" aria-label="Status change explanation" />
                    <button type="button" className="btn" disabled={statusNote.trim().length < 10 || busy || nextStatus === detail.incident.status} onClick={() => void changeStatus()}>
                      Update
                    </button>
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-faint">Closing records your decision and note only. CyberGates does not verify that the underlying security issue is fixed.</p>
                </section>
              </div>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
