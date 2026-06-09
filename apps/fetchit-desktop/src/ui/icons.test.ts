import { describe, expect, it } from "vitest";
import { ICON_NAMES, icon } from "./icons";

describe("icon", () => {
  it("returns a well-formed <svg> on the 24x24 grid for every name", () => {
    for (const name of ICON_NAMES) {
      const el = icon(name);
      expect(el.tagName.toLowerCase()).toBe("svg");
      expect(el.getAttribute("viewBox")).toBe("0 0 24 24");
      expect(el.classList.contains("icon")).toBe(true);
      // A malformed body would surface as a <parsererror> node.
      expect(el.querySelector("parsererror")).toBeNull();
    }
  });

  it("carries no script and no baked color literal, so it stays theme-safe", () => {
    for (const name of ICON_NAMES) {
      const html = icon(name).outerHTML;
      expect(html).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
      expect(html.toLowerCase()).not.toContain("rgb(");
      expect(html.toLowerCase()).not.toContain("<script");
    }
  });

  it("is decorative by default and labelled on request", () => {
    const plain = icon("send");
    expect(plain.getAttribute("aria-hidden")).toBe("true");
    expect(plain.getAttribute("aria-label")).toBeNull();

    const labelled = icon("send", { label: "Send" });
    expect(labelled.getAttribute("role")).toBe("img");
    expect(labelled.getAttribute("aria-label")).toBe("Send");
    expect(labelled.getAttribute("aria-hidden")).toBeNull();
  });

  it("exposes a stable, de-duplicated name list", () => {
    expect(ICON_NAMES.length).toBeGreaterThan(0);
    expect(new Set(ICON_NAMES).size).toBe(ICON_NAMES.length);
  });
});
