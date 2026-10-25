import { describe, expect, it } from "vitest";
import type { Finding } from "../../lib/types";
import { filterFindings } from "./findingFilters";

const findings = [
  { id: "a", severity: "critical", detectedAt: "2026-10-20T12:00:00Z" },
  { id: "b", severity: "low", detectedAt: "2026-10-25T22:00:00Z" },
  { id: "c", severity: "high", detectedAt: "invalid" },
].map((item) => item as Finding);

describe("finding filters", () => {
  it("filters by severity", () => {
    expect(filterFindings(findings, "critical", "", "").map(({ id }) => id)).toEqual(["a"]);
  });

  it("includes both endpoints of the selected calendar dates", () => {
    expect(filterFindings(findings, "all", "2026-10-20", "2026-10-25").map(({ id }) => id)).toEqual(["a", "b"]);
  });

  it("excludes invalid timestamps when a date filter is active", () => {
    expect(filterFindings(findings, "all", "2026-10-01", "").map(({ id }) => id)).toEqual(["a", "b"]);
  });
});
