import { useState } from "react";
import { Braces, RefreshCw } from "lucide-react";
import { ErrorState, Panel, PanelHeader } from "../../components/ui";
import { formatFileSize } from "./fileHash";
import { inspectJsonFile, MAX_JSON_INSPECT_BYTES, type JsonInspection } from "./jsonInspector";

export function JsonInspector({ file }: { file: File | null }) {
  const [result, setResult] = useState<JsonInspection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function inspect() {
    if (!file || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await inspectJsonFile(file));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The file could not be inspected.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel>
      <PanelHeader
        title="JSON structure inspector"
        description="Summarize a selected JSON file without displaying its values or evaluating its contents."
        actions={
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void inspect()}
            disabled={!file || busy || file.size > MAX_JSON_INSPECT_BYTES}
          >
            {busy ? <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden /> : <Braces className="h-3.5 w-3.5" aria-hidden />}
            {busy ? "Inspecting…" : "Inspect JSON"}
          </button>
        }
      />
      <div className="space-y-3 p-5">
        {!file ? (
          <p className="text-sm text-muted">Choose a file above to inspect its JSON structure.</p>
        ) : (
          <p className="text-xs text-muted">
            Selected file: <span className="font-medium text-ink">{file.name}</span> ({formatFileSize(file.size)}).
            Only files up to 1 MiB are accepted.
          </p>
        )}
        {file && file.size > MAX_JSON_INSPECT_BYTES ? (
          <p className="rounded-lg border border-warn/30 bg-warn-soft px-3 py-2 text-xs text-muted">
            This file exceeds the 1 MiB inspection limit. No file contents were read.
          </p>
        ) : null}
        {error ? <ErrorState message={error} onRetry={() => void inspect()} /> : null}
        {result ? (
          <div className="rounded-xl border border-line p-4" aria-live="polite">
            <p className="text-sm font-semibold text-ink">Top-level type: {result.topLevelType}</p>
            {result.objectKeyCount !== undefined ? (
              <>
                <p className="mt-1 text-xs text-muted">{result.objectKeyCount} object keys</p>
                {result.keys?.length ? (
                  <ul className="mt-3 grid gap-1 sm:grid-cols-2">
                    {result.keys.map((entry, index) => (
                      <li key={`${entry.name}-${index}`} className="flex min-w-0 justify-between gap-3 rounded-md bg-surface-2 px-2 py-1 text-xs">
                        <span className="truncate font-medium text-ink">{entry.name}</span>
                        <span className="shrink-0 text-muted">{entry.type}</span>
                      </li>
                    ))}
                  </ul>
                ) : null}
                {result.omittedKeys ? <p className="mt-2 text-xs text-muted">{result.omittedKeys} additional keys omitted.</p> : null}
              </>
            ) : null}
            {result.arrayLength !== undefined ? (
              <>
                <p className="mt-1 text-xs text-muted">
                  {result.arrayLength} array items; summarized {result.arraySampleSize}.
                </p>
                <ul className="mt-3 flex flex-wrap gap-2">
                  {Object.entries(result.arrayTypeCounts ?? {}).map(([type, count]) => (
                    <li key={type} className="chip">{type}: {count}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        ) : null}
        <p className="text-xs leading-relaxed text-muted">
          Inspection is local, bounded to 1 MiB, and does not execute or upload data. It does not validate a schema or determine whether a file is safe.
        </p>
      </div>
    </Panel>
  );
}
