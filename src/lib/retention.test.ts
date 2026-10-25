import { describe, expect, it } from "vitest";
import { requiresRetentionConfirmation } from "./retention";

describe("requiresRetentionConfirmation", () => {
  it("requires confirmation when the retention period is reduced", () => {
    expect(requiresRetentionConfirmation(90, 30)).toBe(true);
  });

  it("does not require confirmation when the period is unchanged or extended", () => {
    expect(requiresRetentionConfirmation(90, 90)).toBe(false);
    expect(requiresRetentionConfirmation(90, 180)).toBe(false);
  });
});
