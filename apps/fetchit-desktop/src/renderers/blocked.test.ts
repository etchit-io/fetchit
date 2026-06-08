import { describe, expect, it } from "vitest";
import { renderBlocked } from "./blocked";

describe("renderBlocked", () => {
  it("renders a blocked-notice card naming the reason", () => {
    const into = document.createElement("div");
    renderBlocked({ kind: "blocked", reason: "xor_name: 4d216f18" }, into);

    const card = into.querySelector(".blocked-notice");
    expect(card).not.toBeNull();
    expect(into.querySelector(".blocked-notice__title")?.textContent).toBe(
      "Content blocked",
    );
    expect(into.querySelector(".blocked-notice__reason")?.textContent).toBe(
      "xor_name: 4d216f18",
    );
  });

  it("inserts the reason as text, never as HTML", () => {
    // Defense-in-depth: the reason is core-generated, but a hostile
    // value must still never reach innerHTML.
    const into = document.createElement("div");
    renderBlocked(
      { kind: "blocked", reason: "<img src=x onerror=alert(1)>" },
      into,
    );
    expect(into.querySelector("img")).toBeNull();
    expect(into.querySelector(".blocked-notice__reason")?.textContent).toBe(
      "<img src=x onerror=alert(1)>",
    );
  });
});
