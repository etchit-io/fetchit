import { renderJson } from "./json";
import { describe, it, expect } from "vitest";

const manifest = JSON.stringify({
  version: 1, agent_id: "a".repeat(64), display_name: "Josh",
  ml_dsa_pubkey: "AA", sig: "BB", issued_at_ms: 1,
});

describe("json profile banner", () => {
  it("shows a profile banner for manifest-shaped JSON and routes to the profile", () => {
    let seen: string | null = null;
    const into = document.createElement("div");
    renderJson({ kind: "json", pretty: manifest } as never, into, (id) => { seen = id; });
    (into.querySelector("[data-act=view-as-profile]") as HTMLElement).click();
    expect(seen).toBe("a".repeat(64));
  });
  it("shows no banner for ordinary JSON", () => {
    const into = document.createElement("div");
    renderJson({ kind: "json", pretty: '{"hello":1}' } as never, into, () => {});
    expect(into.querySelector("[data-act=view-as-profile]")).toBeNull();
  });
});
