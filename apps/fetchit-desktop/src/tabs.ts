import { invoke } from "@tauri-apps/api/core";
import type { Rendition } from "./types";

export type TabStatus = "empty" | "loading" | "rendered" | "error";

export interface Tab {
  id: string;
  address: string | null;
  /** Query string from the address (`?…`), or `""`. Carried into SPAs. */
  query: string;
  shortLabel: string;
  status: TabStatus;
  error: string | null;
  rendition: Rendition | null;
  root: HTMLElement;
  /** Past addresses on this tab, most-recent last. Browser-style back stack. */
  history: string[];
}

type Listener = () => void;

export class TabStore {
  private readonly tabs: Tab[] = [];
  private activeId: string | null = null;
  private readonly listeners = new Set<Listener>();
  private seq = 0;

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  }

  list(): readonly Tab[] {
    return this.tabs;
  }

  active(): Tab | null {
    return this.tabs.find((t) => t.id === this.activeId) ?? null;
  }

  findByAddress(address: string): Tab | null {
    return this.tabs.find((t) => t.address === address) ?? null;
  }

  createEmpty(root: HTMLElement): Tab {
    this.seq += 1;
    const tab: Tab = {
      id: `t${this.seq}`,
      address: null,
      query: "",
      shortLabel: "new tab",
      status: "empty",
      error: null,
      rendition: null,
      root,
      history: [],
    };
    this.tabs.push(tab);
    this.activeId = tab.id;
    this.notify();
    return tab;
  }

  /**
   * Move the tab to `address` (carrying its optional `query`) and mark it
   * loading. When `recordHistory` is true (the default) any non-null
   * previous address is pushed onto the tab's back stack — set false
   * during a back-navigation so we don't record the move we just popped
   * from.
   */
  startFetch(id: string, address: string, recordHistory = true, query = ""): void {
    const tab = this.byId(id);
    if (!tab) return;
    if (recordHistory && tab.address && tab.address !== address) {
      tab.history.push(tab.address);
    }
    tab.address = address;
    tab.query = query;
    tab.shortLabel = shortLabel(address);
    tab.status = "loading";
    tab.error = null;
    tab.rendition = null;
    this.notify();
  }

  /** Pop the most-recent past address off `tab.history`; returns null if empty. */
  popHistory(id: string): string | null {
    const tab = this.byId(id);
    if (!tab) return null;
    return tab.history.pop() ?? null;
  }

  setRendered(id: string, rendition: Rendition): void {
    const tab = this.byId(id);
    if (!tab) return;
    tab.status = "rendered";
    tab.rendition = rendition;
    tab.error = null;
    if (rendition.kind === "etchitEnvelope" && rendition.title) {
      tab.shortLabel = trim(rendition.title, 22);
    }
    this.notify();
  }

  setError(id: string, error: string): void {
    const tab = this.byId(id);
    if (!tab) return;
    tab.status = "error";
    tab.error = error;
    this.notify();
  }

  close(id: string): void {
    const idx = this.tabs.findIndex((t) => t.id === id);
    if (idx < 0) return;
    // Cancel any in-flight fetch for the tab so the Rust task stops
    // making progress instead of running to completion against a DOM
    // root that no longer exists. Fire-and-forget — the backend
    // tolerates no-op cancel calls if no fetch is pending.
    void invoke("cancel_fetch", { tabId: id }).catch(() => {});
    const [removed] = this.tabs.splice(idx, 1);
    removed.root.remove();
    if (this.activeId === id) {
      const next = this.tabs[idx] ?? this.tabs[idx - 1] ?? null;
      this.activeId = next ? next.id : null;
    }
    this.notify();
  }

  activate(id: string): void {
    if (this.activeId === id) return;
    if (!this.tabs.some((t) => t.id === id)) return;
    this.activeId = id;
    this.notify();
  }

  next(): void {
    this.shift(1);
  }

  prev(): void {
    this.shift(-1);
  }

  at(index: number): void {
    const tab = this.tabs[index];
    if (tab) this.activate(tab.id);
  }

  private shift(delta: number): void {
    if (this.tabs.length === 0) return;
    const i = this.tabs.findIndex((t) => t.id === this.activeId);
    const j = ((i + delta) % this.tabs.length + this.tabs.length) % this.tabs.length;
    this.activate(this.tabs[j].id);
  }

  private byId(id: string): Tab | null {
    return this.tabs.find((t) => t.id === id) ?? null;
  }

  private notify(): void {
    for (const fn of this.listeners) fn();
  }
}

function shortLabel(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

function trim(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
