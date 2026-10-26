import { useState, type FormEvent } from "react";
import { AlertTriangle, LoaderCircle, SearchCheck, ShieldCheck, ShieldX } from "lucide-react";
import { ErrorState, Panel, PanelHeader } from "../../components/ui";
import { api } from "../../lib/api";
import type { HostDiagnostic as HostDiagnosticResult } from "../../lib/types";
import { formatRelative } from "../../lib/format";

export function HostDiagnostics() {
  const [host, setHost] = useState("");
  const [result, setResult] = useState<HostDiagnosticResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function runDiagnostic(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requestedHost = host.trim();
    if (!requestedHost || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.diagnoseHost(requestedHost));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="DNS and TLS diagnostics"
        description="Look up a host with the operating system resolver and validate TLS on port 443."
      />
      <div className="space-y-4 p-5">
        <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => void runDiagnostic(event)}>
          <label className="min-w-64 flex-1">
            <span className="mb-1 block text-xs font-medium text-muted">Host name or IP address</span>
            <input
              className="input w-full"
              type="text"
              value={host}
              maxLength={253}
              autoComplete="off"
              spellCheck={false}
              placeholder="example.com"
              onChange={(event) => setHost(event.currentTarget.value)}
            />
          </label>
          <button className="btn btn-primary" type="submit" disabled={!host.trim() || loading}>
            {loading ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> : <SearchCheck className="h-4 w-4" aria-hidden />}
            {loading ? "Checking…" : "Check host"}
          </button>
        </form>

        <div className="flex items-start gap-2 rounded-lg border border-warn/30 bg-warn-soft px-3 py-2 text-xs leading-relaxed text-muted">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" aria-hidden />
          <p>
            Host names are queried through your configured DNS resolver; IP literals are
            used directly. A TLS handshake is opened to port 443, so the resolver and
            remote host can observe the name and connection. CyberGates sends no HTTP
            request, stores no lookup history, and does not assess reputation or safety.
            The request is capped at 30 seconds; a slow system resolver can keep this
            diagnostic unavailable until the resolver returns.
          </p>
        </div>

        {error ? <ErrorState message={error} /> : null}

        {result ? (
          <div className="space-y-3 rounded-xl border border-line p-4" aria-live="polite">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-ink">Results for {result.host}</h3>
              <span className="text-xs text-faint">Checked {formatRelative(result.resolvedAt)}</span>
            </div>
            <div>
              <p className="text-xs font-medium text-muted">Resolved addresses</p>
              {result.addresses.length ? (
                <ul className="mt-1 flex flex-wrap gap-2">
                  {result.addresses.map((address) => (
                    <li key={address} className="chip mono">{address}</li>
                  ))}
                </ul>
              ) : <p className="mt-1 text-xs text-muted">No addresses returned.</p>}
              {result.addressesTruncated ? (
                <p className="mt-2 text-xs text-muted">Only the first 16 distinct addresses are shown.</p>
              ) : null}
            </div>
            <div className={`rounded-lg border px-3 py-3 ${result.tls.verified ? "border-ok/30 bg-ok-soft" : "border-warn/30 bg-warn-soft"}`}>
              <div className="flex items-center gap-2">
                {result.tls.verified
                  ? <ShieldCheck className="h-4 w-4 text-ok" aria-hidden />
                  : <ShieldX className="h-4 w-4 text-warn" aria-hidden />}
                <p className="text-sm font-medium text-ink">
                  {result.tls.verified ? "TLS certificate verified" : "TLS could not be verified"}
                </p>
              </div>
              {result.tls.verified ? (
                <dl className="mt-3 grid gap-x-5 gap-y-2 text-xs sm:grid-cols-2">
                  <div><dt className="text-muted">Connected address</dt><dd className="mono mt-0.5">{result.tls.peerAddress}</dd></div>
                  <div><dt className="text-muted">Protocol</dt><dd className="mono mt-0.5">{result.tls.protocol ?? "Unavailable"}</dd></div>
                  <div><dt className="text-muted">Cipher suite</dt><dd className="mono mt-0.5 break-all">{result.tls.cipherSuite ?? "Unavailable"}</dd></div>
                  <div><dt className="text-muted">Certificate chain</dt><dd className="mt-0.5">{result.tls.certificateChainLength} certificate(s)</dd></div>
                  {result.tls.leafSha256 ? (
                    <div className="sm:col-span-2"><dt className="text-muted">Leaf certificate SHA-256</dt><dd className="mono mt-0.5 break-all">{result.tls.leafSha256}</dd></div>
                  ) : null}
                </dl>
              ) : (
                <p className="mt-2 break-words text-xs text-muted">{result.tls.error ?? "No TLS details were returned."}</p>
              )}
            </div>
            <p className="text-xs leading-relaxed text-muted">{result.scopeNote}</p>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}
