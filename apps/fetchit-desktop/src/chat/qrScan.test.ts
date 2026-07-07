import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { jsQRMock } = vi.hoisted(() => ({
  jsQRMock: vi.fn<
    (
      data: Uint8ClampedArray,
      width: number,
      height: number,
    ) => { data: string } | null
  >(),
}));

vi.mock("jsqr", () => ({ default: jsQRMock }));

import {
  decodeFrame,
  QrScanError,
  scanErrorCopy,
  scanQrFromCamera,
} from "./qrScan";

const DECODED = "x0x://pair/" + "ab".repeat(32) + "?r=https%3A%2F%2Frelay.example";

function fakeFrame(): ImageData {
  return {
    data: new Uint8ClampedArray(16),
    width: 2,
    height: 2,
  } as unknown as ImageData;
}

interface FakeVideo {
  el: HTMLVideoElement;
  playCalls: () => number;
}

function fakeVideo(): FakeVideo {
  const play = vi.fn(() => Promise.resolve());
  const el = {
    srcObject: null as MediaStream | null,
    muted: false,
    readyState: 2,
    videoWidth: 640,
    videoHeight: 480,
    setAttribute: vi.fn(),
    play,
  } as unknown as HTMLVideoElement;
  return { el, playCalls: () => play.mock.calls.length };
}

interface FakeStream {
  stream: MediaStream;
  stopCalls: () => number;
}

function fakeStream(): FakeStream {
  const stop = vi.fn();
  const tracks = [{ stop }, { stop }];
  const stream = { getTracks: () => tracks } as unknown as MediaStream;
  return { stream, stopCalls: () => stop.mock.calls.length };
}

beforeEach(() => {
  jsQRMock.mockReset();
  // Deterministic, fast loop scheduling in jsdom.
  vi.stubGlobal("requestAnimationFrame", (cb: () => void) => {
    setTimeout(cb, 0);
    return 0;
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("decodeFrame", () => {
  it("forwards the frame's data/width/height to jsQR", () => {
    jsQRMock.mockReturnValueOnce(null);
    const frame = fakeFrame();
    decodeFrame(frame);
    expect(jsQRMock).toHaveBeenCalledWith(frame.data, 2, 2);
  });

  it("returns the decoded text on a hit", () => {
    jsQRMock.mockReturnValueOnce({ data: DECODED });
    expect(decodeFrame(fakeFrame())).toBe(DECODED);
  });

  it("returns null when jsQR finds nothing", () => {
    jsQRMock.mockReturnValueOnce(null);
    expect(decodeFrame(fakeFrame())).toBeNull();
  });

  it("treats an empty decode as no hit", () => {
    jsQRMock.mockReturnValueOnce({ data: "" });
    expect(decodeFrame(fakeFrame())).toBeNull();
  });
});

describe("scanQrFromCamera", () => {
  it("resolves the first decoded string and stops the stream", async () => {
    const { el } = fakeVideo();
    const { stream, stopCalls } = fakeStream();
    const getUserMedia = vi.fn(() => Promise.resolve(stream));
    const decode = vi
      .fn<(f: ImageData) => string | null>()
      .mockReturnValueOnce(null)
      .mockReturnValueOnce(null)
      .mockReturnValue(DECODED);

    const result = await scanQrFromCamera({
      video: el,
      signal: new AbortController().signal,
      media: { getUserMedia },
      grabFrame: () => fakeFrame(),
      decode,
    });

    expect(result).toBe(DECODED);
    expect(decode).toHaveBeenCalledTimes(3);
    expect(stopCalls()).toBe(2);
    expect(el.srcObject).toBeNull();
  });

  it("asks for the rear camera as an ideal (never hard) constraint", async () => {
    const { el } = fakeVideo();
    const { stream } = fakeStream();
    const getUserMedia = vi.fn(() => Promise.resolve(stream));

    await scanQrFromCamera({
      video: el,
      signal: new AbortController().signal,
      media: { getUserMedia },
      grabFrame: () => fakeFrame(),
      decode: () => DECODED,
    });

    expect(getUserMedia).toHaveBeenCalledWith({
      audio: false,
      video: { facingMode: { ideal: "environment" } },
    });
  });

  it("resolves null on cancel and stops the stream", async () => {
    const { el } = fakeVideo();
    const { stream, stopCalls } = fakeStream();
    const controller = new AbortController();

    const scan = scanQrFromCamera({
      video: el,
      signal: controller.signal,
      media: { getUserMedia: () => Promise.resolve(stream) },
      grabFrame: () => fakeFrame(),
      decode: () => null,
    });
    // Let the loop spin a few frames before cancelling.
    await new Promise((r) => setTimeout(r, 5));
    controller.abort();

    await expect(scan).resolves.toBeNull();
    expect(stopCalls()).toBe(2);
    expect(el.srcObject).toBeNull();
  });

  it("resolves null without opening the camera when already aborted", async () => {
    const { el } = fakeVideo();
    const controller = new AbortController();
    controller.abort();
    const getUserMedia = vi.fn();

    const result = await scanQrFromCamera({
      video: el,
      signal: controller.signal,
      media: { getUserMedia },
    });

    expect(result).toBeNull();
    expect(getUserMedia).not.toHaveBeenCalled();
  });

  it("stops the stream when the signal aborted while the camera opened", async () => {
    const { el } = fakeVideo();
    const { stream, stopCalls } = fakeStream();
    const controller = new AbortController();
    const getUserMedia = vi.fn(() => {
      controller.abort();
      return Promise.resolve(stream);
    });

    const result = await scanQrFromCamera({
      video: el,
      signal: controller.signal,
      media: { getUserMedia },
    });

    expect(result).toBeNull();
    expect(stopCalls()).toBe(2);
  });

  it("rejects with kind 'denied' when permission is blocked", async () => {
    const { el } = fakeVideo();
    await expect(
      scanQrFromCamera({
        video: el,
        signal: new AbortController().signal,
        media: {
          getUserMedia: () => Promise.reject({ name: "NotAllowedError" }),
        },
      }),
    ).rejects.toMatchObject({ name: "QrScanError", kind: "denied" });
  });

  it("rejects with kind 'no-camera' when no device exists", async () => {
    const { el } = fakeVideo();
    await expect(
      scanQrFromCamera({
        video: el,
        signal: new AbortController().signal,
        media: {
          getUserMedia: () => Promise.reject({ name: "NotFoundError" }),
        },
      }),
    ).rejects.toMatchObject({ name: "QrScanError", kind: "no-camera" });
  });

  it("rejects with kind 'unavailable' when the webview has no camera API", async () => {
    // jsdom's navigator has no mediaDevices, which is exactly the case
    // under test: no injected media and no platform API.
    const { el } = fakeVideo();
    await expect(
      scanQrFromCamera({
        video: el,
        signal: new AbortController().signal,
      }),
    ).rejects.toMatchObject({ name: "QrScanError", kind: "unavailable" });
  });

  it("retries without constraints when facingMode over-constrains", async () => {
    const { el } = fakeVideo();
    const { stream } = fakeStream();
    const getUserMedia = vi
      .fn<() => Promise<MediaStream>>()
      .mockRejectedValueOnce({ name: "OverconstrainedError" })
      .mockResolvedValueOnce(stream);

    const result = await scanQrFromCamera({
      video: el,
      signal: new AbortController().signal,
      media: { getUserMedia },
      grabFrame: () => fakeFrame(),
      decode: () => DECODED,
    });

    expect(result).toBe(DECODED);
    expect(getUserMedia).toHaveBeenCalledTimes(2);
    expect(getUserMedia).toHaveBeenLastCalledWith({
      audio: false,
      video: true,
    });
  });

  it("classifies a failed unconstrained retry as no-camera", async () => {
    const { el } = fakeVideo();
    const getUserMedia = vi
      .fn<() => Promise<MediaStream>>()
      .mockRejectedValueOnce({ name: "OverconstrainedError" })
      .mockRejectedValueOnce({ name: "NotFoundError" });

    await expect(
      scanQrFromCamera({
        video: el,
        signal: new AbortController().signal,
        media: { getUserMedia },
      }),
    ).rejects.toMatchObject({ kind: "no-camera" });
  });

  it("stops the stream when the viewfinder fails to start", async () => {
    const { el } = fakeVideo();
    (el as { play: () => Promise<void> }).play = () =>
      Promise.reject(new Error("no autoplay"));
    const { stream, stopCalls } = fakeStream();

    await expect(
      scanQrFromCamera({
        video: el,
        signal: new AbortController().signal,
        media: { getUserMedia: () => Promise.resolve(stream) },
      }),
    ).rejects.toMatchObject({ kind: "unavailable" });
    expect(stopCalls()).toBe(2);
  });

  it("skips decode until a frame is available", async () => {
    const { el } = fakeVideo();
    const { stream } = fakeStream();
    const decode = vi.fn<(f: ImageData) => string | null>(() => DECODED);
    const grabFrame = vi
      .fn<() => ImageData | null>()
      .mockReturnValueOnce(null)
      .mockReturnValue(fakeFrame());

    const result = await scanQrFromCamera({
      video: el,
      signal: new AbortController().signal,
      media: { getUserMedia: () => Promise.resolve(stream) },
      grabFrame,
      decode,
    });

    expect(result).toBe(DECODED);
    expect(decode).toHaveBeenCalledTimes(1);
  });
});

describe("scanErrorCopy", () => {
  it("names the missing camera and offers the paste fallback", () => {
    expect(scanErrorCopy(new QrScanError("no-camera", "x"))).toBe(
      "No camera found on this computer. Paste the invite link instead.",
    );
  });

  it("names the blocked permission and offers the paste fallback", () => {
    expect(scanErrorCopy(new QrScanError("denied", "x"))).toBe(
      "Camera access was blocked. You can paste the invite link instead.",
    );
  });

  it("falls back to generic copy for anything else", () => {
    expect(scanErrorCopy(new Error("boom"))).toBe(
      "Couldn't start the camera. You can paste the invite link instead.",
    );
    expect(scanErrorCopy(new QrScanError("unavailable", "x"))).toBe(
      "Couldn't start the camera. You can paste the invite link instead.",
    );
  });
});
