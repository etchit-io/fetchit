import { describe, expect, it, vi } from "vitest";
import { DEMO_CITY_INDEX, buildEmptyState } from "./emptyState";

describe("buildEmptyState", () => {
  it("DEMO_CITY_INDEX is a canonical 64-hex address", () => {
    expect(DEMO_CITY_INDEX).toMatch(/^[0-9a-f]{64}$/);
  });

  it("renders both the demo CTA and the address-bar hint", () => {
    const root = buildEmptyState(() => undefined);
    const cta = root.querySelector<HTMLButtonElement>(
      '[data-testid="empty-demo-cta"]',
    );
    expect(cta).not.toBeNull();
    expect(cta?.tagName).toBe("BUTTON");
    expect(cta?.type).toBe("button");
    expect(cta?.textContent).toMatch(/demo city/i);

    const hint = root.querySelector<HTMLParagraphElement>(".tab-empty-hint");
    expect(hint?.textContent).toMatch(/paste an autonomi address/i);
  });

  it("invokes onDemo exactly once per click on the CTA", () => {
    const onDemo = vi.fn();
    const root = buildEmptyState(onDemo);
    const cta = root.querySelector<HTMLButtonElement>(
      '[data-testid="empty-demo-cta"]',
    );
    expect(cta).not.toBeNull();
    cta?.click();
    expect(onDemo).toHaveBeenCalledTimes(1);
    cta?.click();
    expect(onDemo).toHaveBeenCalledTimes(2);
  });

  it("hint is not a button — only the CTA fires the navigation", () => {
    const onDemo = vi.fn();
    const root = buildEmptyState(onDemo);
    const hint = root.querySelector<HTMLParagraphElement>(".tab-empty-hint");
    hint?.click();
    expect(onDemo).not.toHaveBeenCalled();
  });
});
