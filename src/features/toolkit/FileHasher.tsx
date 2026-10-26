import { useState } from "react";
import { FileKey, RefreshCw, ShieldCheck } from "lucide-react";
import { EmptyState, ErrorState, PageHeader, Panel, PanelHeader } from "../../components/ui";
import { formatFileSize, inspectFileSignature, MAX_HASH_FILE_BYTES, sha256File } from "./fileHash";

export function FileHasher() {
  const [file, setFile] = useState<File | null>(null);
  const [digest, setDigest] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [inspecting, setInspecting] = useState(false);
  const [signatureInfo, setSignatureInfo] = useState<Awaited<ReturnType<typeof inspectFileSignature>> | null>(null);

  async function hashSelectedFile() {
    if (!file || busy) return;
    setBusy(true);
    setError(null);
    setDigest(null);
    try {
      setDigest(await sha256File(file));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function inspectSelectedFile() {
    if (!file || inspecting) return;
    setInspecting(true);
    setError(null);
    setSignatureInfo(null);
    try {
      setSignatureInfo(await inspectFileSignature(file));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setInspecting(false);
    }
  }

  return (
    <div className="fade-in">
      <PageHeader
        title="Security Toolkit"
        subtitle="Defensive utilities for file inspection. Selected file contents are read locally and never uploaded or executed."
      />
      <Panel>
        <PanelHeader
          title="SHA-256 file hash"
          description="Select one file to calculate its cryptographic digest and display basic metadata."
        />
        <div className="space-y-4 p-5">
          <div className="flex flex-wrap items-center gap-3">
            <input
              type="file"
              className="input max-w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-surface-3 file:px-3 file:py-1.5 file:text-ink"
              aria-label="Choose a file to hash"
              onChange={(event) => {
                const nextFile = event.currentTarget.files?.[0] ?? null;
                event.currentTarget.value = "";
                setFile(nextFile);
                setDigest(null);
                setSignatureInfo(null);
                setError(null);
              }}
            />
            <button
              type="button"
              className="btn btn-primary"
              disabled={!file || busy || file.size > MAX_HASH_FILE_BYTES}
              onClick={() => void hashSelectedFile()}
            >
              {busy ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden /> : <FileKey className="h-4 w-4" aria-hidden />}
              {busy ? "Hashing…" : "Calculate SHA-256"}
            </button>
            <button
              type="button"
              className="btn"
              disabled={!file || inspecting}
              onClick={() => void inspectSelectedFile()}
            >
              {inspecting ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden /> : <ShieldCheck className="h-4 w-4" aria-hidden />}
              {inspecting ? "Inspecting…" : "Inspect file signature"}
            </button>
          </div>

          {file ? (
            <dl className="grid gap-3 rounded-xl border border-line bg-surface-2 p-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-xs text-muted">File name</dt>
                <dd className="mt-1 break-all font-medium">{file.name}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Size</dt>
                <dd className="mt-1">{formatFileSize(file.size)}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Browser-reported type</dt>
                <dd className="mt-1 break-all">{file.type || "Not provided by the operating system"}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted">Last modified</dt>
                <dd className="mt-1">{file.lastModified ? new Date(file.lastModified).toLocaleString() : "Unknown"}</dd>
              </div>
            </dl>
          ) : (
            <EmptyState
              title="Choose a file"
              description="The browser file picker grants access only to the file you select. CyberGates does not execute the file."
              icon={<ShieldCheck className="h-5 w-5" aria-hidden />}
            />
          )}

          {file && file.size > MAX_HASH_FILE_BYTES ? (
            <p className="rounded-lg border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-muted">
              This file exceeds the 64 MiB limit. Choose a smaller file to avoid excessive memory use.
            </p>
          ) : null}
          {error ? <ErrorState message={error} onRetry={() => void hashSelectedFile()} /> : null}
          {digest ? (
            <div className="rounded-xl border border-line p-4">
              <p className="text-xs text-muted">SHA-256</p>
              <p className="mono mt-2 break-all text-sm" aria-live="polite">{digest}</p>
            </div>
          ) : null}
          {signatureInfo ? (
            <div className="rounded-xl border border-line p-4" aria-live="polite">
              <p className="text-xs text-muted">Header signature (first 4 KiB)</p>
              <p className="mt-2 text-sm font-medium text-ink">
                {signatureInfo.signature?.label ?? "No recognized signature"}
              </p>
              {signatureInfo.extensionMismatch ? (
                <p className="mt-2 rounded-lg border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-muted">
                  The file extension “.{signatureInfo.extension}” does not match this recognized header. This can be benign; it is not a malware verdict.
                </p>
              ) : null}
              <p className="mt-2 text-xs text-muted">
                Header checks are best-effort and can be forged or incomplete. They do not validate the entire file or determine whether it is safe.
              </p>
            </div>
          ) : null}
          <p className="text-xs leading-relaxed text-muted">
            Hashing identifies the selected file contents; it does not determine whether a file is safe or malicious.
            The file is processed in this app only, is not saved by CyberGates, and is limited to 64 MiB.
          </p>
        </div>
      </Panel>
      <div className="mt-5">
        <Panel className="p-5">
          <h2 className="font-semibold text-ink">More toolkit capabilities</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">
            Certificate chain details, IP/domain reputation, and safe format decoders are not implemented yet. Recent CyberGates application logs are available in the panel below. DNS and TLS checks only inspect the host you enter; they do not provide reputation or safety verdicts.
            CyberGates does not make reputation or malware claims from a file hash alone.
          </p>
        </Panel>
      </div>
    </div>
  );
}
