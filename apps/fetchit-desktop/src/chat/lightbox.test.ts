import { describe, it, expect } from "vitest";
import { openImageLightbox } from "./lightbox";
import type { Attachment } from "./types";

const ATT: Attachment = {
  mime: "image/png",
  width: 4,
  height: 4,
  bytes_b64: "iVBORw0KAAA=",
};

function host(): HTMLElement | null {
  return document.querySelector(".chat-lightbox");
}

// The overlay is a webkit2gtk-safe singleton (built once, reused), so the
// tests share one host across the suite and do not clear document.body.
describe("openImageLightbox", () => {
  it("shows an overlay with the image rendered from the data URL", () => {
    openImageLightbox(ATT);
    const h = host();
    expect(h).not.toBeNull();
    expect(h!.hidden).toBe(false);
    const img = h!.querySelector("img");
    expect(img).not.toBeNull();
    expect(img!.getAttribute("src")).toBe("data:image/png;base64,iVBORw0KAAA=");
  });

  it("closes on Escape", () => {
    openImageLightbox(ATT);
    expect(host()!.hidden).toBe(false);
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(host()!.hidden).toBe(true);
  });

  it("closes when the backdrop is clicked but not the image panel", () => {
    openImageLightbox(ATT);
    const h = host()!;
    const panel = h.querySelector(".chat-lightbox__panel") as HTMLElement;
    panel.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(h.hidden).toBe(false);
    h.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(h.hidden).toBe(true);
  });

  it("closes on the close button", () => {
    openImageLightbox(ATT);
    const h = host()!;
    const close = h.querySelector(".chat-lightbox__close") as HTMLButtonElement;
    close.click();
    expect(h.hidden).toBe(true);
  });

  it("reuses one host element across repeated opens", () => {
    openImageLightbox(ATT);
    openImageLightbox({ ...ATT, bytes_b64: "AAAA" });
    expect(document.querySelectorAll(".chat-lightbox").length).toBe(1);
    expect(host()!.querySelector("img")!.getAttribute("src")).toBe(
      "data:image/png;base64,AAAA",
    );
  });
});
