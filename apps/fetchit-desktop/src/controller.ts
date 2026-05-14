import { invoke } from "@tauri-apps/api/core";
import type { Rendition } from "./types";
import { TabStore } from "./tabs";
import { render as renderRendition } from "./renderers/dispatch";
import { mountTabStrip } from "./ui/tabStrip";
import { mountAddressBar, type AddressBarApi } from "./ui/addressBar";
import { bindKeyboard } from "./ui/keyboard";
import { initMediaBase } from "./mediaUrl";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

export async function init(): Promise<void> {
  // Resolve the local media-server URL before any render can happen.
  // Renderers and the rewriter rely on it synchronously.
  try {
    await initMediaBase();
  } catch (err) {
    console.error("[fetchit] media server URL unavailable:", err);
  }
  const input = need<HTMLInputElement>("addr");
  const button = need<HTMLButtonElement>("go");
  const statusEl = need<HTMLElement>("status");
  const stripEl = need<HTMLElement>("tabs");
  const stageEl = need<HTMLElement>("stage");

  const store = new TabStore();

  const bar: AddressBarApi = mountAddressBar(input, button, {
    onSubmit: (addr) => submit(addr, store, stageEl),
    onInvalid: (msg) => {
      statusEl.textContent = msg;
    },
  });

  const newTab = (): void => {
    const root = buildStageRoot(stageEl);
    root.appendChild(buildEmptyState());
    store.createEmpty(root);
    bar.focus();
  };

  mountTabStrip(stripEl, store, newTab);
  bindKeyboard(store, newTab);

  store.subscribe(() => {
    const active = store.active();
    for (const t of store.list()) {
      t.root.classList.toggle("is-active", !!active && t.id === active.id);
    }
    if (!bar.isFocused()) bar.setValue(active && active.address ? active.address : "");
    statusEl.textContent = statusFor(active);
    button.disabled = active?.status === "loading";
  });

  bindIframeMessages(store, stageEl);
  bar.focus();
}

// Dev-only diagnostic forwarder. In production builds (vite build) the early
// return makes this a no-op — no IPC, no daemon-log spam. Mirrors protocol.rs's
// `diag!` macro on the Rust side; the matching no-op there is what makes both
// safe to keep in committed code.
function dlog(line: string): void {
  if (!import.meta.env.DEV) return;
  void invoke("log", { line }).catch(() => {});
}

// In-iframe address links postMessage one of three shapes:
//   { kind: "fetchit:open", address, target } — link click, navigate or new-tab;
//   { kind: "fetchit:back" }                  — magic <a href="fetchit://back">;
//   { kind: "fetchit:log",  text }            — dev-only diagnostic.
function bindIframeMessages(store: TabStore, stage: HTMLElement): void {
  window.addEventListener("message", (e) => {
    const data = e.data as
      | { kind?: unknown; address?: unknown; target?: unknown; text?: unknown }
      | null;
    if (!data || typeof data !== "object") return;
    if (data.kind === "fetchit:log") {
      if (typeof data.text === "string") dlog(`[iframe] ${data.text}`);
      return;
    }
    if (data.kind === "fetchit:back") {
      dlog(`[parent] back-link received`);
      backNavigate(store);
      return;
    }
    if (data.kind !== "fetchit:open") return;
    const addr = typeof data.address === "string" ? data.address : "";
    if (!HEX_64.test(addr)) {
      dlog(`[parent] postMessage rejected: bad address ${String(data.address).slice(0, 16)}`);
      return;
    }
    const wantsNew = data.target === "new";
    dlog(`[parent] navigate addr=${addr.slice(0, 8)}… newTab=${wantsNew}`);
    navigate(addr.toLowerCase(), store, stage, wantsNew);
  });
}

function backNavigate(store: TabStore): void {
  const active = store.active();
  if (!active) return;
  const prev = store.popHistory(active.id);
  if (!prev) {
    dlog(`[parent] back ignored: no history`);
    return;
  }
  dlog(`[parent] back to addr=${prev.slice(0, 8)}…`);
  startIn(active, prev, store, false);
}

function navigate(addr: string, store: TabStore, stage: HTMLElement, newTab: boolean): void {
  if (newTab) {
    startIn(store.createEmpty(buildStageRoot(stage)), addr, store);
    return;
  }
  const active = store.active();
  const target = active ?? store.createEmpty(buildStageRoot(stage));
  startIn(target, addr, store);
}

function submit(addr: string, store: TabStore, stage: HTMLElement): void {
  const existing = store.findByAddress(addr);
  if (existing) {
    store.activate(existing.id);
    if (existing.status === "error") startIn(existing, addr, store);
    return;
  }
  const active = store.active();
  const target = active && active.status === "empty" ? active : store.createEmpty(buildStageRoot(stage));
  startIn(target, addr, store);
}

function startIn(
  tab: { id: string; root: HTMLElement },
  addr: string,
  store: TabStore,
  recordHistory = true,
): void {
  tab.root.replaceChildren(buildSpinner());
  store.startFetch(tab.id, addr, recordHistory);
  void runFetch(addr, tab.id, tab.root, store);
}

async function runFetch(
  addr: string,
  id: string,
  root: HTMLElement,
  store: TabStore,
): Promise<void> {
  dlog(`[fetch] start addr=${addr.slice(0, 8)}…`);
  try {
    const r = await invoke<Rendition>("fetch_and_render", { addr });
    dlog(`[fetch] done addr=${addr.slice(0, 8)}… kind=${r.kind}`);
    renderRendition(r, root, addr);
    store.setRendered(id, r);
  } catch (e) {
    const msg = errorMessage(e);
    dlog(`[fetch] fail addr=${addr.slice(0, 8)}… msg=${msg}`);
    root.replaceChildren(buildErrorState(msg));
    store.setError(id, msg);
  }
}

function buildStageRoot(stage: HTMLElement): HTMLElement {
  const root = document.createElement("section");
  root.className = "tab-content";
  root.setAttribute("role", "tabpanel");
  stage.appendChild(root);
  return root;
}

function buildEmptyState(): HTMLElement {
  const e = document.createElement("div");
  e.className = "tab-empty";
  e.textContent = "paste an address above to fetch";
  return e;
}

function buildSpinner(): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "tab-spinner";
  wrap.setAttribute("aria-label", "loading");
  wrap.setAttribute("role", "status");
  const ring = document.createElement("div");
  ring.className = "tab-spinner-ring";
  wrap.appendChild(ring);
  return wrap;
}

function buildErrorState(msg: string): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "tab-error";
  const heading = document.createElement("p");
  heading.className = "tab-error-heading";
  heading.textContent = "fetch failed";
  const detail = document.createElement("p");
  detail.className = "tab-error-detail";
  detail.textContent = msg;
  wrap.append(heading, detail);
  return wrap;
}

function statusFor(active: ReturnType<TabStore["active"]>): string {
  if (!active) return "";
  if (active.status === "loading") return "fetching… (the first connection takes a moment)";
  if (active.status === "error") return `fetch failed: ${active.error ?? "(unknown)"}`;
  return "";
}

function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

function need<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
}
