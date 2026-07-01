import { beforeEach, describe, expect, it, vi } from "vitest";
import { TabStore } from "./tabs";
import type { Rendition } from "./types";

const A = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const B = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

function root(): HTMLElement {
  return document.createElement("section");
}

describe("TabStore", () => {
  let store: TabStore;

  beforeEach(() => {
    store = new TabStore();
  });

  it("starts empty with no active tab", () => {
    expect(store.list()).toEqual([]);
    expect(store.active()).toBeNull();
  });

  describe("createEmpty", () => {
    it("creates an empty tab, activates it, and notifies", () => {
      const fn = vi.fn();
      store.subscribe(fn);
      const tab = store.createEmpty(root());
      expect(tab.status).toBe("empty");
      expect(tab.address).toBeNull();
      expect(tab.shortLabel).toBe("new tab");
      expect(store.active()).toBe(tab);
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("assigns unique sequential ids", () => {
      const a = store.createEmpty(root()).id;
      const b = store.createEmpty(root()).id;
      expect(a).not.toBe(b);
    });
  });

  describe("startFetch", () => {
    it("transitions an empty tab to loading with the given address", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      const after = store.active();
      expect(after?.status).toBe("loading");
      expect(after?.address).toBe(A);
      expect(after?.shortLabel).toBe(`${A.slice(0, 6)}…${A.slice(-4)}`);
    });

    it("is a no-op for unknown ids", () => {
      const fn = vi.fn();
      store.subscribe(fn);
      store.startFetch("does-not-exist", A);
      expect(fn).not.toHaveBeenCalled();
    });
  });

  describe("setRendered / setError", () => {
    it("marks rendered with the rendition", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      const r: Rendition = { kind: "text", language: null, body: "hello" };
      store.setRendered(tab.id, r);
      expect(store.active()?.status).toBe("rendered");
      expect(store.active()?.rendition).toBe(r);
      expect(store.active()?.error).toBeNull();
    });

    it("uses the etchit envelope title as the short label", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      const r: Rendition = {
        kind: "etchitEnvelope",
        title: "My Document",
        content: "body",
        language: null,
      };
      store.setRendered(tab.id, r);
      expect(store.active()?.shortLabel).toBe("My Document");
    });

    it("truncates very long titles", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      const r: Rendition = {
        kind: "etchitEnvelope",
        title: "This title is much longer than the cap",
        content: "",
        language: null,
      };
      store.setRendered(tab.id, r);
      const label = store.active()?.shortLabel ?? "";
      expect(label.length).toBeLessThanOrEqual(22);
      expect(label.endsWith("…")).toBe(true);
    });

    it("captures an error message", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      store.setError(tab.id, "network down");
      expect(store.active()?.status).toBe("error");
      expect(store.active()?.error).toBe("network down");
    });
  });

  describe("renderProfile", () => {
    it("marks a tab rendered with a display label and no rendition", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, `profile:${"a".repeat(64)}`);
      store.renderProfile(tab.id, "@josh@etchit.io");
      const t = store.active()!;
      expect(t.status).toBe("rendered");
      expect(t.rendition).toBeNull();
      expect(t.display).toBe("@josh@etchit.io");
      expect(t.shortLabel).toBe("@josh@etchit.io");
    });
  });

  describe("findByAddress", () => {
    it("returns the tab when a matching address exists", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      expect(store.findByAddress(A)?.id).toBe(tab.id);
    });

    it("returns null for unknown addresses", () => {
      expect(store.findByAddress(A)).toBeNull();
    });

    it("does not match empty tabs (address is null)", () => {
      store.createEmpty(root());
      expect(store.findByAddress(A)).toBeNull();
    });
  });

  describe("close", () => {
    it("removes the tab and detaches its root from the DOM", () => {
      const r = root();
      document.body.appendChild(r);
      const tab = store.createEmpty(r);
      store.close(tab.id);
      expect(store.list()).toEqual([]);
      expect(r.parentNode).toBeNull();
    });

    it("activates the next tab when closing the active one", () => {
      const t1 = store.createEmpty(root());
      const t2 = store.createEmpty(root());
      store.activate(t1.id);
      store.close(t1.id);
      expect(store.active()?.id).toBe(t2.id);
    });

    it("falls back to the previous tab when closing the last one", () => {
      const t1 = store.createEmpty(root());
      store.createEmpty(root());
      // active is now t2 (the last createEmpty activated it)
      store.close(store.active()!.id);
      expect(store.active()?.id).toBe(t1.id);
    });

    it("leaves activeId null when the only tab is closed", () => {
      const tab = store.createEmpty(root());
      store.close(tab.id);
      expect(store.active()).toBeNull();
    });

    it("is a no-op for unknown ids", () => {
      const fn = vi.fn();
      store.createEmpty(root());
      store.subscribe(fn);
      store.close("nonsense");
      expect(fn).not.toHaveBeenCalled();
    });
  });

  describe("activate / next / prev / at", () => {
    it("activate is a no-op when the id is already active", () => {
      const fn = vi.fn();
      const tab = store.createEmpty(root());
      store.subscribe(fn);
      store.activate(tab.id);
      expect(fn).not.toHaveBeenCalled();
    });

    it("activate is a no-op for unknown ids", () => {
      const fn = vi.fn();
      store.createEmpty(root());
      store.subscribe(fn);
      store.activate("nonsense");
      expect(fn).not.toHaveBeenCalled();
    });

    it("next cycles forward through tabs", () => {
      const t1 = store.createEmpty(root());
      const t2 = store.createEmpty(root());
      store.activate(t1.id);
      store.next();
      expect(store.active()?.id).toBe(t2.id);
      store.next();
      expect(store.active()?.id).toBe(t1.id);
    });

    it("prev cycles backward through tabs", () => {
      const t1 = store.createEmpty(root());
      const t2 = store.createEmpty(root());
      store.activate(t1.id);
      store.prev();
      expect(store.active()?.id).toBe(t2.id);
    });

    it("at(n) jumps to the nth tab", () => {
      const t1 = store.createEmpty(root());
      const t2 = store.createEmpty(root());
      store.at(0);
      expect(store.active()?.id).toBe(t1.id);
      store.at(1);
      expect(store.active()?.id).toBe(t2.id);
    });

    it("at(n) ignores out-of-range indices", () => {
      const tab = store.createEmpty(root());
      store.at(5);
      expect(store.active()?.id).toBe(tab.id);
    });
  });

  describe("subscribe", () => {
    it("returns an unsubscribe function that stops further notifications", () => {
      const fn = vi.fn();
      const off = store.subscribe(fn);
      store.createEmpty(root());
      expect(fn).toHaveBeenCalledTimes(1);
      off();
      store.createEmpty(root());
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("notifies multiple subscribers", () => {
      const fa = vi.fn();
      const fb = vi.fn();
      store.subscribe(fa);
      store.subscribe(fb);
      store.createEmpty(root());
      expect(fa).toHaveBeenCalledTimes(1);
      expect(fb).toHaveBeenCalledTimes(1);
    });
  });

  describe("history (back stack)", () => {
    it("an empty tab has an empty history", () => {
      const tab = store.createEmpty(root());
      expect(tab.history).toEqual([]);
    });

    it("the first navigation from empty doesn't record history", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      expect(store.active()?.history).toEqual([]);
    });

    it("subsequent navigations push the previous address onto history", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      store.startFetch(tab.id, B);
      expect(store.active()?.history).toEqual([A]);
    });

    it("startFetch(recordHistory=false) skips pushing — used by back-nav", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      store.startFetch(tab.id, B);
      store.startFetch(tab.id, A, false);
      expect(store.active()?.history).toEqual([A]);
    });

    it("popHistory returns the most-recent past address and shortens history", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      store.startFetch(tab.id, B);
      expect(store.popHistory(tab.id)).toBe(A);
      expect(store.active()?.history).toEqual([]);
    });

    it("popHistory returns null on a tab with no history", () => {
      const tab = store.createEmpty(root());
      expect(store.popHistory(tab.id)).toBeNull();
    });

    it("popHistory returns null for unknown ids", () => {
      expect(store.popHistory("nonsense")).toBeNull();
    });

    it("doesn't push when the new address equals the current one", () => {
      const tab = store.createEmpty(root());
      store.startFetch(tab.id, A);
      store.startFetch(tab.id, A);
      expect(store.active()?.history).toEqual([]);
    });
  });

  describe("multi-tab independence", () => {
    it("two open tabs with different addresses don't collide", () => {
      const ta = store.createEmpty(root());
      store.startFetch(ta.id, A);
      const tb = store.createEmpty(root());
      store.startFetch(tb.id, B);
      expect(store.findByAddress(A)?.id).toBe(ta.id);
      expect(store.findByAddress(B)?.id).toBe(tb.id);
    });
  });
});
