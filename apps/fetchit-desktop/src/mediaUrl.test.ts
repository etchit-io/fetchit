import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn<(cmd: string, args?: unknown) => Promise<unknown>>();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: unknown) => invokeMock(cmd, args),
}));

beforeEach(async () => {
  invokeMock.mockReset();
  vi.resetModules();
});

describe("mediaBase", () => {
  it("throws when called before initMediaBase or setMediaBaseForTesting", async () => {
    const { mediaBase } = await import("./mediaUrl");
    expect(() => mediaBase()).toThrowError(
      /call initMediaBase\(\) before rendering media/,
    );
  });
});

describe("mediaUrlOf", () => {
  it("concatenates base and address with a single slash", async () => {
    const { mediaUrlOf, setMediaBaseForTesting } = await import("./mediaUrl");
    setMediaBaseForTesting("http://127.0.0.1:5555");
    const addr = "a".repeat(64);
    expect(mediaUrlOf(addr)).toBe(`http://127.0.0.1:5555/${addr}`);
  });

  it("reflects the value set by setMediaBaseForTesting without any IPC call", async () => {
    const { mediaBase, mediaUrlOf, setMediaBaseForTesting } = await import(
      "./mediaUrl"
    );
    setMediaBaseForTesting("http://127.0.0.1:1234");
    expect(mediaBase()).toBe("http://127.0.0.1:1234");
    expect(mediaUrlOf("abc")).toBe("http://127.0.0.1:1234/abc");
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("appends the address verbatim — no case-folding, no encoding, no validation", async () => {
    const { mediaUrlOf, setMediaBaseForTesting } = await import("./mediaUrl");
    setMediaBaseForTesting("http://127.0.0.1:9000");

    const upper = "ABCDEF".repeat(10) + "ABCD";
    const lower = upper.toLowerCase();

    expect(mediaUrlOf(upper)).toBe(`http://127.0.0.1:9000/${upper}`);
    expect(mediaUrlOf(lower)).toBe(`http://127.0.0.1:9000/${lower}`);
    expect(mediaUrlOf("")).toBe("http://127.0.0.1:9000/");
  });

  it("setMediaBaseForTesting overrides a previously cached value", async () => {
    const { mediaBase, mediaUrlOf, setMediaBaseForTesting, initMediaBase } =
      await import("./mediaUrl");
    invokeMock.mockResolvedValueOnce("http://127.0.0.1:1111");
    await initMediaBase();
    expect(mediaBase()).toBe("http://127.0.0.1:1111");

    setMediaBaseForTesting("http://127.0.0.1:2222");
    expect(mediaBase()).toBe("http://127.0.0.1:2222");
    expect(mediaUrlOf("xyz")).toBe("http://127.0.0.1:2222/xyz");
  });
});

describe("initMediaBase", () => {
  it("returns the value resolved by invoke('media_url_base') and caches it", async () => {
    const { initMediaBase, mediaBase } = await import("./mediaUrl");
    invokeMock.mockResolvedValueOnce("http://127.0.0.1:7777");

    const base = await initMediaBase();
    expect(base).toBe("http://127.0.0.1:7777");
    expect(mediaBase()).toBe("http://127.0.0.1:7777");
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock).toHaveBeenCalledWith("media_url_base", undefined);
  });

  it("caches the result and does not re-issue the IPC on subsequent calls", async () => {
    const { initMediaBase } = await import("./mediaUrl");
    invokeMock.mockResolvedValueOnce("http://127.0.0.1:8888");

    const first = await initMediaBase();
    const second = await initMediaBase();

    expect(first).toBe("http://127.0.0.1:8888");
    expect(second).toBe("http://127.0.0.1:8888");
    expect(invokeMock).toHaveBeenCalledTimes(1);
  });
});
