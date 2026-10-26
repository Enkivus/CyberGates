import { describe, expect, it } from "vitest";
import { inspectJsonFile, MAX_JSON_INSPECT_BYTES } from "./jsonInspector";

describe("bounded JSON structure inspection", () => {
  it("summarizes object keys without returning values", async () => {
    const file = new File(['{"name":"private value","items":[1,null],"__proto__":true}'], "data.json");
    const result = await inspectJsonFile(file);

    expect(result.topLevelType).toBe("object");
    expect(result.objectKeyCount).toBe(3);
    expect(result.keys).toEqual([
      { name: "name", type: "string" },
      { name: "items", type: "array" },
      { name: "__proto__", type: "boolean" },
    ]);
    expect(JSON.stringify(result)).not.toContain("private value");
  });

  it("summarizes only a bounded sample of array item types", async () => {
    const values = Array.from({ length: 600 }, (_, index) => index % 2 === 0 ? index : null);
    const result = await inspectJsonFile(new File([JSON.stringify(values)], "data.json"));

    expect(result.arrayLength).toBe(600);
    expect(result.arraySampleSize).toBe(500);
    expect(result.arrayTypeCounts).toEqual({ number: 250, null: 250 });
  });

  it("rejects malformed JSON and invalid UTF-8", async () => {
    await expect(inspectJsonFile(new File(["{broken"], "bad.json")))
      .rejects.toThrow("The selected file is not valid JSON.");
    await expect(inspectJsonFile(new File([new Uint8Array([0xff, 0xfe])], "bad.json")))
      .rejects.toThrow("The selected file is not valid UTF-8 JSON.");
  });

  it("rejects oversized files before reading their content", async () => {
    const file = new File([new Uint8Array(MAX_JSON_INSPECT_BYTES + 1)], "large.json");
    await expect(inspectJsonFile(file)).rejects.toThrow("JSON inspection is limited to 1 MiB.");
  });
});
