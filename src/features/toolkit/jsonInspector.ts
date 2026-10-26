export const MAX_JSON_INSPECT_BYTES = 1024 * 1024;
const MAX_OBJECT_KEYS = 100;
const ARRAY_SAMPLE_SIZE = 500;

export type JsonValueType = "object" | "array" | "string" | "number" | "boolean" | "null";

export interface JsonInspection {
  topLevelType: JsonValueType;
  objectKeyCount?: number;
  keys?: Array<{ name: string; type: JsonValueType }>;
  omittedKeys?: number;
  arrayLength?: number;
  arraySampleSize?: number;
  arrayTypeCounts?: Partial<Record<JsonValueType, number>>;
}

export async function inspectJsonFile(file: File): Promise<JsonInspection> {
  if (file.size > MAX_JSON_INSPECT_BYTES) {
    throw new Error("JSON inspection is limited to 1 MiB.");
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
  } catch {
    throw new Error("The selected file is not valid UTF-8 JSON.");
  }

  try {
    const value: unknown = JSON.parse(text.replace(/^\uFEFF/, ""));
    const topLevelType = getJsonValueType(value);
    if (topLevelType === "object") {
      const record = value as Record<string, unknown>;
      const allKeys = Object.keys(record);
      const keys = allKeys.slice(0, MAX_OBJECT_KEYS).map((name) => ({
        name: name.slice(0, 256),
        type: getJsonValueType(record[name]),
      }));
      return {
        topLevelType,
        objectKeyCount: allKeys.length,
        keys,
        omittedKeys: Math.max(0, allKeys.length - keys.length),
      };
    }
    if (topLevelType === "array") {
      const array = value as unknown[];
      const sample = array.slice(0, ARRAY_SAMPLE_SIZE);
      const arrayTypeCounts: Partial<Record<JsonValueType, number>> = {};
      for (const item of sample) {
        const type = getJsonValueType(item);
        arrayTypeCounts[type] = (arrayTypeCounts[type] ?? 0) + 1;
      }
      return {
        topLevelType,
        arrayLength: array.length,
        arraySampleSize: sample.length,
        arrayTypeCounts,
      };
    }
    return { topLevelType };
  } catch {
    throw new Error("The selected file is not valid JSON.");
  }
}

function getJsonValueType(value: unknown): JsonValueType {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "object") return "object";
  return typeof value as "string" | "number" | "boolean";
}
