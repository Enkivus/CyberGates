import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatUptime,
  severityOrder,
  titleCase,
} from "./format";

describe("format helpers", () => {
  it("formats byte sizes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1024 * 1024 * 3)).toBe("3.0 MB");
  });

  it("formats uptime", () => {
    expect(formatUptime(0)).toBe("—");
    expect(formatUptime(90)).toBe("1m");
    expect(formatUptime(3660)).toBe("1h 1m");
    expect(formatUptime(90000)).toBe("1d 1h");
  });

  it("normalizes labels", () => {
    expect(titleCase("threat_protection")).toBe("Threat Protection");
    expect(severityOrder.critical).toBeGreaterThan(severityOrder.info);
  });
});
