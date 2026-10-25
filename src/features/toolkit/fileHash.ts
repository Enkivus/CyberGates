export const MAX_HASH_FILE_BYTES = 64 * 1024 * 1024;
export const FILE_SIGNATURE_BYTES = 4096;

export type FileSignature = {
  label: string;
  extensions: string[];
};

const knownSignatures: FileSignature[] = [
  { label: "PDF document", extensions: ["pdf"] },
  { label: "PNG image", extensions: ["png"] },
  { label: "JPEG image", extensions: ["jpg", "jpeg", "jpe"] },
  { label: "GIF image", extensions: ["gif"] },
  { label: "WebP image", extensions: ["webp"] },
  { label: "ZIP archive or ZIP-based document", extensions: ["zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"] },
  { label: "gzip-compressed data", extensions: ["gz", "tgz"] },
  { label: "7-Zip archive", extensions: ["7z"] },
  { label: "RAR archive", extensions: ["rar"] },
  { label: "SQLite database", extensions: ["db", "sqlite", "sqlite3"] },
  { label: "ELF executable or shared object", extensions: ["elf", "so"] },
  { label: "Windows PE executable or library", extensions: ["exe", "dll", "sys"] },
  { label: "Mach-O executable or library", extensions: ["dylib", "bundle"] },
  { label: "Mach-O universal binary", extensions: ["dylib", "bundle"] },
  { label: "Script with an interpreter declaration", extensions: ["sh", "bash", "py", "pl", "rb", "js", "command"] },
];

function startsWith(bytes: Uint8Array, signature: number[]): boolean {
  return signature.every((byte, index) => bytes[index] === byte);
}

function detectPe(bytes: Uint8Array): boolean {
  if (!startsWith(bytes, [0x4d, 0x5a]) || bytes.length < 0x40) return false;
  const offset = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0x3c, true);
  return offset + 4 <= bytes.length && startsWith(bytes.subarray(offset), [0x50, 0x45, 0, 0]);
}

function detectSignature(bytes: Uint8Array): FileSignature | null {
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return knownSignatures[0];
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return knownSignatures[1];
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return knownSignatures[2];
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) || startsWith(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])) return knownSignatures[3];
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWith(bytes.subarray(8), [0x57, 0x45, 0x42, 0x50])) return knownSignatures[4];
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06]) || startsWith(bytes, [0x50, 0x4b, 0x07, 0x08])) return knownSignatures[5];
  if (startsWith(bytes, [0x1f, 0x8b])) return knownSignatures[6];
  if (startsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return knownSignatures[7];
  if (startsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return knownSignatures[8];
  if (startsWith(bytes, [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0])) return knownSignatures[9];
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return knownSignatures[10];
  if (detectPe(bytes)) return knownSignatures[11];
  const macho = [
    [0xfe, 0xed, 0xfa, 0xce], [0xce, 0xfa, 0xed, 0xfe], [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca],
    [0xca, 0xfe, 0xba, 0xbf], [0xbf, 0xba, 0xfe, 0xca],
  ];
  if (macho.some((magic) => startsWith(bytes, magic))) {
    return startsWith(bytes, [0xca, 0xfe]) || startsWith(bytes, [0xbe, 0xba]) || startsWith(bytes, [0xbf, 0xba])
      ? knownSignatures[13]
      : knownSignatures[12];
  }
  if (startsWith(bytes, [0x23, 0x21])) return knownSignatures[14];
  return null;
}

export async function inspectFileSignature(file: File): Promise<{
  signature: FileSignature | null;
  extension: string;
  extensionMismatch: boolean;
}> {
  const bytes = new Uint8Array(await file.slice(0, FILE_SIGNATURE_BYTES).arrayBuffer());
  const signature = detectSignature(bytes);
  const extensionIndex = file.name.lastIndexOf(".");
  const extension = extensionIndex > 0 ? file.name.slice(extensionIndex + 1).toLowerCase() : "";
  const hasExtension = extension.length > 0;
  return {
    signature,
    extension,
    extensionMismatch: Boolean(signature && hasExtension && !signature.extensions.includes(extension)),
  };
}

export async function sha256File(file: File): Promise<string> {
  if (file.size > MAX_HASH_FILE_BYTES) {
    throw new Error("Files larger than 64 MiB are not supported by this browser-based tool.");
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("Secure SHA-256 hashing is unavailable in this webview.");
  }

  const digest = await globalThis.crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}
