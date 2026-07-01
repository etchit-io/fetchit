import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  extractAutonomiAddresses,
  mountAutonomiPreview,
} from "./bubblePreview";

const invokeMock = vi.fn<(cmd: string, args?: unknown) => Promise<unknown>>();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: unknown) => invokeMock(cmd, args),
}));

const ADDR = "f".repeat(64);

let host: HTMLElement;

beforeEach(() => {
  invokeMock.mockReset();
  host = document.createElement("div");
  document.body.appendChild(host);
});

afterEach(() => {
  host.remove();
});

describe("extractAutonomiAddresses", () => {
  it("returns 64-hex addresses in order, deduped", () => {
    const body = `before autonomi://${ADDR} then autonomi://${ADDR} and autonomi://${"a".repeat(64)} end`;
    expect(extractAutonomiAddresses(body)).toEqual([ADDR, "a".repeat(64)]);
  });

  it("ignores non-64-hex matches", () => {
    expect(extractAutonomiAddresses("autonomi://abc")).toEqual([]);
  });
});

describe("mountAutonomiPreview", () => {
  it("renders Preview + Open buttons with the truncated address", () => {
    mountAutonomiPreview(host, ADDR, { onOpen: () => {} });
    const label = host.querySelector(".chat-preview__addr")!;
    expect(label.textContent).toContain("autonomi://");
    expect(label.textContent).toContain("…");
    expect(host.querySelectorAll(".chat-preview__btn").length).toBe(2);
  });

  it("Open button calls onOpen with full autonomi:// URI", () => {
    const onOpen = vi.fn();
    mountAutonomiPreview(host, ADDR, { onOpen });
    const btns = host.querySelectorAll<HTMLButtonElement>(".chat-preview__btn");
    btns[1].click();
    expect(onOpen).toHaveBeenCalledWith(`autonomi://${ADDR}`);
  });

  it("skips invalid addresses", () => {
    mountAutonomiPreview(host, "not-hex", { onOpen: () => {} });
    expect(host.children.length).toBe(0);
  });

  it("renders text rendition inline on Preview click", async () => {
    invokeMock.mockResolvedValueOnce({
      kind: "text",
      language: "plaintext",
      body: "hello from autonomi",
    });
    mountAutonomiPreview(host, ADDR, { onOpen: () => {} });
    const previewBtn = host.querySelectorAll<HTMLButtonElement>(
      ".chat-preview__btn",
    )[0];
    previewBtn.click();
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    const slot = host.querySelector(".chat-preview__slot") as HTMLElement;
    expect(slot.hidden).toBe(false);
    expect(slot.dataset.kind).toBe("text");
    expect(slot.textContent).toContain("hello from autonomi");
  });

  it("falls back to Open-in-reader for heavy kinds (pdf, html, video, audio)", async () => {
    invokeMock.mockResolvedValueOnce({ kind: "pdf", byteLen: 12345 });
    const onOpen = vi.fn();
    mountAutonomiPreview(host, ADDR, { onOpen });
    host.querySelectorAll<HTMLButtonElement>(".chat-preview__btn")[0].click();
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    const heavy = host.querySelector(".chat-preview__heavy")!;
    expect(heavy.textContent).toContain("PDF");
    const openInReader = heavy.querySelector<HTMLButtonElement>(
      ".chat-preview__btn",
    )!;
    openInReader.click();
    expect(onOpen).toHaveBeenCalledWith(`autonomi://${ADDR}`);
  });

  it("surfaces fetch failures and leaves Preview re-clickable", async () => {
    invokeMock.mockRejectedValueOnce(new Error("nope"));
    mountAutonomiPreview(host, ADDR, { onOpen: () => {} });
    const previewBtn = host.querySelectorAll<HTMLButtonElement>(
      ".chat-preview__btn",
    )[0];
    previewBtn.click();
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    const status = host.querySelector(".chat-preview__status") as HTMLElement;
    expect(status.textContent).toContain("nope");
    expect(previewBtn.disabled).toBe(false);
  });
});
