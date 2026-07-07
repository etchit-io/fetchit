// Camera QR scanning for the add-contact flow, split into two seams:
// `decodeFrame` (pure ImageData → string, a thin jsQR wrapper; jsqr is
// Apache-2.0) and `scanQrFromCamera` (getUserMedia + per-frame decode
// loop). The camera stream always stops on exit — success, cancel, or
// error — so the OS camera indicator never outlives the scan.
//
// This module runs in the main webview only. Rendered network content
// cannot reach the camera: it runs inside a sandboxed null-origin
// iframe whose `navigator.mediaDevices` is locked to `undefined`
// before any SPA script runs (src/renderers/htmlRewriter.ts).

import jsQR from "jsqr";

/** Why a scan could not run, mapped to specific user-facing copy. */
export type QrScanFailure = "no-camera" | "denied" | "unavailable";

/** Typed scan error so the dialog can show specific, actionable copy. */
export class QrScanError extends Error {
  /** The failure classification. */
  readonly kind: QrScanFailure;

  constructor(kind: QrScanFailure, message: string) {
    super(message);
    this.name = "QrScanError";
    this.kind = kind;
  }
}

/** Plain-English copy for a scan failure; always offers the paste fallback. */
export function scanErrorCopy(e: unknown): string {
  const kind = e instanceof QrScanError ? e.kind : "unavailable";
  if (kind === "no-camera") {
    return "No camera found on this computer. Paste the invite link instead.";
  }
  if (kind === "denied") {
    return "Camera access was blocked. You can paste the invite link instead.";
  }
  return "Couldn't start the camera. You can paste the invite link instead.";
}

/** Decode one video frame; `null` when no QR code is present. */
export function decodeFrame(frame: ImageData): string | null {
  const hit = jsQR(frame.data, frame.width, frame.height);
  return hit !== null && hit.data.length > 0 ? hit.data : null;
}

export interface ScanQrOptions {
  /** Viewfinder element the camera stream is attached to. */
  video: HTMLVideoElement;
  /** Aborting resolves the scan with `null` (user cancel). */
  signal: AbortSignal;
  /** Camera source; defaults to `navigator.mediaDevices`. Test seam. */
  media?: Pick<MediaDevices, "getUserMedia">;
  /** Frame capture; defaults to a canvas grab. Test seam. */
  grabFrame?: (video: HTMLVideoElement) => ImageData | null;
  /** Frame decoder; defaults to `decodeFrame`. Test seam. */
  decode?: (frame: ImageData) => string | null;
}

/// Open the camera, attach it to `opts.video`, and decode frames until
/// a QR code is found (resolves its text), the signal aborts (resolves
/// `null`), or the camera can't be opened (rejects with `QrScanError`).
export async function scanQrFromCamera(
  opts: ScanQrOptions,
): Promise<string | null> {
  const { video, signal } = opts;
  if (signal.aborted) return null;
  const media = opts.media ?? navigator.mediaDevices;
  if (!media?.getUserMedia) {
    throw new QrScanError(
      "unavailable",
      "camera API unavailable in this webview",
    );
  }
  const stream = await openCamera(media);
  if (signal.aborted) {
    stopStream(stream, video);
    return null;
  }
  const grabFrame = opts.grabFrame ?? makeFrameGrabber();
  const decode = opts.decode ?? decodeFrame;
  video.srcObject = stream;
  video.muted = true;
  video.setAttribute("playsinline", "true");
  try {
    try {
      await video.play();
    } catch (e) {
      throw new QrScanError(
        "unavailable",
        `viewfinder failed to start: ${String(e)}`,
      );
    }
    return await decodeLoop(video, signal, grabFrame, decode);
  } finally {
    stopStream(stream, video);
  }
}

/// Prefer the rear camera where one exists; `ideal` never
/// over-constrains, so a laptop's single user-facing camera still
/// matches. Engines that treat facingMode as hard get one
/// unconstrained retry before we conclude no camera exists.
async function openCamera(
  media: Pick<MediaDevices, "getUserMedia">,
): Promise<MediaStream> {
  try {
    return await media.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" } },
    });
  } catch (e) {
    if (errorName(e) === "OverconstrainedError") {
      try {
        return await media.getUserMedia({ audio: false, video: true });
      } catch (retryError) {
        throw classifyCameraError(retryError);
      }
    }
    throw classifyCameraError(e);
  }
}

function errorName(e: unknown): string {
  if (e instanceof Error) return e.name;
  if (typeof e === "object" && e !== null && "name" in e) {
    return String((e as { name: unknown }).name);
  }
  return "";
}

function classifyCameraError(e: unknown): QrScanError {
  const name = errorName(e);
  if (
    name === "NotAllowedError"
    || name === "PermissionDeniedError"
    || name === "SecurityError"
  ) {
    return new QrScanError("denied", `camera permission: ${name}`);
  }
  if (
    name === "NotFoundError"
    || name === "DevicesNotFoundError"
    || name === "OverconstrainedError"
  ) {
    return new QrScanError("no-camera", `no usable camera: ${name}`);
  }
  return new QrScanError("unavailable", `camera failed: ${name || String(e)}`);
}

// Decode work is capped at this dimension: jsQR cost grows with pixel
// count and a 640-800px frame is the sweet spot for QR detection, so
// full 1080p+ webcam frames are scaled down before decoding.
const MAX_DECODE_DIM = 800;

function makeFrameGrabber(): (video: HTMLVideoElement) => ImageData | null {
  const canvas = document.createElement("canvas");
  return (video) => {
    // readyState 2 = HAVE_CURRENT_DATA: at least one frame is up.
    if (video.readyState < 2 || video.videoWidth === 0) return null;
    const scale = Math.min(
      1,
      MAX_DECODE_DIM / Math.max(video.videoWidth, video.videoHeight),
    );
    const w = Math.max(1, Math.round(video.videoWidth * scale));
    const h = Math.max(1, Math.round(video.videoHeight * scale));
    if (canvas.width !== w) canvas.width = w;
    if (canvas.height !== h) canvas.height = h;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    ctx.drawImage(video, 0, 0, w, h);
    return ctx.getImageData(0, 0, w, h);
  };
}

function decodeLoop(
  video: HTMLVideoElement,
  signal: AbortSignal,
  grabFrame: (video: HTMLVideoElement) => ImageData | null,
  decode: (frame: ImageData) => string | null,
): Promise<string | null> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value: string | null): void => {
      if (done) return;
      done = true;
      resolve(value);
    };
    signal.addEventListener("abort", () => finish(null), { once: true });
    const tick = (): void => {
      if (done) return;
      if (signal.aborted) {
        finish(null);
        return;
      }
      const frame = grabFrame(video);
      const text = frame ? decode(frame) : null;
      if (text !== null) {
        finish(text);
        return;
      }
      schedule(tick);
    };
    tick();
  });
}

// requestAnimationFrame is absent or throttled in headless
// environments (jsdom); fall back to a timer so the loop advances.
function schedule(cb: () => void): void {
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(cb);
  } else {
    setTimeout(cb, 66);
  }
}

function stopStream(stream: MediaStream, video: HTMLVideoElement): void {
  for (const track of stream.getTracks()) track.stop();
  if (video.srcObject === stream) video.srcObject = null;
}
