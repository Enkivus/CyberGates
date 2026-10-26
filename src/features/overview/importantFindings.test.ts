import { describe, expect, it } from "vitest";
import type { Finding } from "../../lib/types";
import { countNewImportantFindings } from "./importantFindings";

function finding(
  checkId: string,
  severity: Finding["severity"] = "high",
  status = "open",
): Finding {
  return {
    id: `finding-${checkId}`,
    auditId: "audit",
    checkId,
    title: checkId,
    severity,
    status,
    category: "test",
    evidence: "private evidence",
    explanation: "explanation",
    remediation: "remediation",
    verification: "verification",
    source: "test",
    detectedAt: "2026-10-26T00:00:00Z",
    resolvedAt: null,
  };
}

describe("important finding notices", () => {
  it("counts only newly open critical or high checks", () => {
    expect(countNewImportantFindings(
      [finding("already-open")],
      [
        finding("already-open"),
        finding("new-critical", "critical"),
        finding("new-low", "low"),
        finding("resolved", "critical", "resolved"),
      ],
    )).toBe(1);
  });

  it("notifies when a previously resolved important check reopens", () => {
    expect(countNewImportantFindings(
      [finding("reopened", "high", "resolved")],
      [finding("reopened")],
    )).toBe(1);
  });

  it("deduplicates repeated checks and does not notify on first load", () => {
    expect(countNewImportantFindings([], [finding("same"), { ...finding("same"), id: "duplicate" }])).toBe(1);
    expect(countNewImportantFindings([], [])).toBe(0);
  });
});
