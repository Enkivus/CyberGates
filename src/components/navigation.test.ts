import { describe, expect, it } from "vitest";
import { searchNavItems } from "./navigation";

describe("searchNavItems", () => {
  it("returns every section for an empty query", () => {
    expect(searchNavItems(" ")).toHaveLength(15);
  });

  it("matches section names without case sensitivity", () => {
    expect(searchNavItems("FIREWALL").map((item) => item.to)).toEqual([
      "/firewall",
    ]);
  });

  it("also matches navigation groups", () => {
    expect(searchNavItems("response").map((item) => item.to)).toEqual([
      "/incidents",
      "/backup",
    ]);
  });
});
