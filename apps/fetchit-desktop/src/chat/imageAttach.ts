// Client-side inline-image attachment handling: validate, sniff, encode.
//
// This is the UI half of spec 2.4. The authoritative validation is
// Bob's `fetchit_chat::attachment` (enforced on both send and receive),
// but we re-check here as defense-in-depth so a malformed or hostile
// image never reaches the render sink, and so the user gets an honest
// rejection at attach time instead of a silent backend strip. The MIME
// is decided by magic-byte sniff, never the file's declared type — an
// `<svg>` renamed `.png` is rejected because its bytes don't match a
// raster signature.

import type { Attachment } from "./types";

/// Maximum RAW image size (pre-base64). Mirrors
/// `fetchit_chat::attachment::MAX_ATTACHMENT_BYTES` (256 KiB). Larger
/// images should be shared via an `autonomi://` link instead.
export const MAX_ATTACHMENT_BYTES = 256 * 1024;

/// Raster formats permitted inline. `image/svg+xml` is deliberately
/// absent: SVG can embed script, an XSS vector when rendered.
export const ALLOWED_ATTACHMENT_MIMES = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
] as const;

/// Identify a raster image purely from its leading magic bytes. Returns
/// the canonical MIME or null when the bytes are not one of the allowed
/// raster formats (SVG, HTML, and anything else fall through to null).
export function sniffRasterMime(bytes: Uint8Array): string | null {
  // JPEG: FF D8 FF
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    bytes.length >= 8
    && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47
    && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a
  ) {
    return "image/png";
  }
  // GIF: "GIF87a" or "GIF89a"
  if (
    bytes.length >= 6
    && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38
    && (bytes[4] === 0x37 || bytes[4] === 0x39) && bytes[5] === 0x61
  ) {
    return "image/gif";
  }
  // WEBP: "RIFF" <u32 len> "WEBP"
  if (
    bytes.length >= 12
    && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46
    && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  return null;
}

/// Result of validating raw image bytes for inline attachment.
export type ImageValidation = { ok: true; mime: string } | { ok: false; error: string };

/// Validate raw bytes against the size cap and the raster allowlist.
/// Size is checked first so an oversize blob is rejected as "too large"
/// regardless of its header. The returned `mime` is the sniffed type,
/// never a caller-supplied string.
export function validateImageBytes(bytes: Uint8Array): ImageValidation {
  if (bytes.length > MAX_ATTACHMENT_BYTES) {
    return {
      ok: false,
      error: `Image is too large (max ${Math.floor(MAX_ATTACHMENT_BYTES / 1024)} KB). Share larger images with an autonomi:// link.`,
    };
  }
  const mime = sniffRasterMime(bytes);
  if (!mime) {
    return { ok: false, error: "Only JPEG, PNG, GIF, or WebP images can be attached." };
  }
  return { ok: true, mime };
}

const B64_CHUNK = 0x8000;

/// Standard base64 (no line wrapping) of raw bytes. Chunked so a large
/// buffer doesn't blow the argument limit of `String.fromCharCode`.
export function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += B64_CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + B64_CHUNK));
  }
  return btoa(binary);
}

/// Inverse of [`bytesToB64`].
export function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/// The `data:` URL an `<img>` renders directly. The MIME is the
/// validated raster type, so the browser interprets the bytes as that
/// raster format and never as markup.
export function attachmentDataUrl(att: Attachment): string {
  return `data:${att.mime};base64,${att.bytes_b64}`;
}

/// Reads an image's intrinsic dimensions from a data URL. Injectable so
/// unit tests don't need a real image decoder.
export type DimReader = (dataUrl: string) => Promise<{ width: number; height: number }>;

function defaultReadDims(dataUrl: string): Promise<{ width: number; height: number }> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () =>
      resolve({ width: img.naturalWidth || 1, height: img.naturalHeight || 1 });
    img.onerror = () => reject(new Error("Could not decode the image."));
    img.src = dataUrl;
  });
}

/// Read a Blob's bytes. Prefers the modern `arrayBuffer()` (real
/// webview) and falls back to `FileReader` for environments that lack
/// it (jsdom under test).
function readFileBytes(file: Blob): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === "function") {
    return file.arrayBuffer().then((b) => new Uint8Array(b));
  }
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(new Uint8Array(fr.result as ArrayBuffer));
    fr.onerror = () => reject(fr.error ?? new Error("Could not read the file."));
    fr.readAsArrayBuffer(file);
  });
}

/// Read a picked file, validate it, and build a wire-ready
/// [`Attachment`]. Throws (with a user-facing message) when the bytes
/// are oversize or not an allowed raster image.
export async function fileToAttachment(
  file: File,
  readDims: DimReader = defaultReadDims,
): Promise<Attachment> {
  const bytes = await readFileBytes(file);
  const v = validateImageBytes(bytes);
  if (!v.ok) throw new Error(v.error);
  const bytes_b64 = bytesToB64(bytes);
  const { width, height } = await readDims(`data:${v.mime};base64,${bytes_b64}`);
  return { mime: v.mime, width, height, bytes_b64 };
}
