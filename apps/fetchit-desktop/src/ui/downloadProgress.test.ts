import { describe, expect, it } from "vitest";
import { renderProgress } from "./downloadProgress";

function root(): HTMLElement {
  return document.createElement("div");
}

describe("renderProgress", () => {
  it("builds a progress bar on the first event", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "fetching", done: 0, total: 100 });
    expect(r.querySelector(".tab-progress")).not.toBeNull();
    expect(r.querySelector(".tab-progress-fill")).not.toBeNull();
  });

  it("fills proportionally to done / total", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "fetching", done: 50, total: 100 });
    expect(r.querySelector<HTMLElement>(".tab-progress-fill")?.style.width).toBe(
      "50%",
    );
  });

  it("labels the fetching phase with a percentage", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "fetching", done: 25, total: 100 });
    expect(r.querySelector(".tab-progress-label")?.textContent).toBe(
      "fetching 25%",
    );
  });

  it("labels the resolving phase without a percentage", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "resolving", done: 1, total: 3 });
    expect(r.querySelector(".tab-progress-label")?.textContent).toBe(
      "resolving…",
    );
  });

  it("clamps progress that exceeds the total to 100%", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "fetching", done: 120, total: 100 });
    expect(r.querySelector<HTMLElement>(".tab-progress-fill")?.style.width).toBe(
      "100%",
    );
  });

  it("treats a zero total as 0%", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "fetching", done: 0, total: 0 });
    expect(r.querySelector<HTMLElement>(".tab-progress-fill")?.style.width).toBe(
      "0%",
    );
  });

  it("reuses the same bar element on subsequent events", () => {
    const r = root();
    renderProgress(r, { address: "a", phase: "fetching", done: 10, total: 100 });
    const first = r.querySelector(".tab-progress");
    renderProgress(r, { address: "a", phase: "fetching", done: 60, total: 100 });
    expect(r.querySelector(".tab-progress")).toBe(first);
    expect(r.querySelector<HTMLElement>(".tab-progress-fill")?.style.width).toBe(
      "60%",
    );
  });
});
