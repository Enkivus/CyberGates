import type { Finding, Severity } from "../../lib/types";

export function filterFindings(
  findings: Finding[],
  severity: Severity | "all",
  dateFrom: string,
  dateTo: string,
): Finding[] {
  const from = dateFrom ? new Date(`${dateFrom}T00:00:00`).getTime() : null;
  const to = dateTo ? new Date(`${dateTo}T23:59:59.999`).getTime() : null;

  return findings.filter((finding) => {
    if (severity !== "all" && finding.severity !== severity) return false;
    if (from === null && to === null) return true;
    const detected = Date.parse(finding.detectedAt);
    if (!Number.isFinite(detected)) return false;
    if (from !== null && detected < from) return false;
    if (to !== null && detected > to) return false;
    return true;
  });
}
