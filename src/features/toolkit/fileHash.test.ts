import { describe, expect, it, vi } from "vitest";
import {
  formatFileSize,
  FILE_SIGNATURE_BYTES,
  inspectFileSignature,
  MAX_HASH_FILE_BYTES,
  sha256File,
} from "./fileHash";

describe("local file hash helpers", () => {
  it("calculates a SHA-256 digest without uploading the file", async () => {
    const file = new File(["abc"], "fixture.txt", { type: "text/plain" });
    await expect(sha256File(file)).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("rejects files above its memory bound before reading content", async () => {
    const arrayBuffer = vi.fn();
    const oversized = { size: MAX_HASH_FILE_BYTES + 1, arrayBuffer } as unknown as File;
    await expect(sha256File(oversized)).rejects.toThrow("larger than 64 MiB");
    expect(arrayBuffer).not.toHaveBeenCalled();
  });

  it("formats selected-file metadata sizes", () => {
    expect(formatFileSize(0)).toBe("0 B");
    expect(formatFileSize(1024)).toBe("1.00 KiB");
    expect(formatFileSize(10 * 1024)).toBe("10.0 KiB");
    expect(formatFileSize(-1)).toBe("Unknown");
  });

  it("recognizes a PDF header and flags a contradictory extension", async () => {
    const file = new File(["%PDF-1.7"], "report.png");
    await expect(inspectFileSignature(file)).resolves.toMatchObject({
      signature: { label: "PDF document" },
      extension: "png",
      extensionMismatch: true,
    });
  });

  it("does not flag a ZIP-based document extension as a mismatch", async () => {
    const file = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], "report.docx");
    await expect(inspectFileSignature(file)).resolves.toMatchObject({
      signature: { label: "ZIP archive or ZIP-based document" },
      extensionMismatch: false,
    });
  });

  it("reports unknown headers without guessing from the extension", async () => {
    const file = new File(["not a recognized format"], "notes.txt");
    await expect(inspectFileSignature(file)).resolves.toMatchObject({
      signature: null,
      extensionMismatch: false,
    });
  });

  it("reads only the bounded header for signature inspection", async () => {
    const file = new File(["%PDF-1.7" + "x".repeat(10_000)], "large.pdf");
    const slice = vi.spyOn(file, "slice");
    await inspectFileSignature(file);
    expect(slice).toHaveBeenCalledWith(0, FILE_SIGNATURE_BYTES);
  });
});
