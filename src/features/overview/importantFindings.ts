import type { Finding } from "../../lib/types";

export function countNewImportantFindings(
  previous: Finding[],
  current: Finding[],
): number {
  const previousOpen = new Set(
    previous
      .filter(isOpenImportantFinding)
      .map((finding) => finding.checkId),
  );
  const currentOpen = new Set(
    current
      .filter(isOpenImportantFinding)
      .map((finding) => finding.checkId),
  );
  return [...currentOpen].filter((checkId) => !previousOpen.has(checkId)).length;
}

function isOpenImportantFinding(finding: Finding): boolean {
  return finding.status === "open" &&
    (finding.severity === "critical" || finding.severity === "high");
}
