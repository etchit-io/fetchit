import { listen } from "@tauri-apps/api/event";
import type { TabStore } from "../tabs";

/** Payload of the backend `download-progress` event (`src-tauri/src/lib.rs`). */
export interface DownloadProgress {
  /** 64-hex address of the fetch in flight. */
  address: string;
  /** `"resolving"` (walking the data map) then `"fetching"` (content). */
  phase: string;
  /** Chunks completed in the current phase. */
  done: number;
  /** Total chunks in the current phase; `0` until known. */
  total: number;
}

/**
 * Render a progress bar into the loading tab as backend
 * `download-progress` events arrive. The backend emits these only when
 * the on-disk cache is enabled — the one path it streams — so with the
 * cache off no events come and the loading spinner simply stays.
 */
export function mountDownloadProgress(store: TabStore): void {
  void listen<DownloadProgress>("download-progress", ({ payload }) => {
    const want = payload.address.toLowerCase();
    const tab = store
      .list()
      .find((t) => t.status === "loading" && t.address?.toLowerCase() === want);
    if (tab) renderProgress(tab.root, payload);
  });
}

/**
 * Draw or update the progress bar inside `root`. The first call replaces
 * the loading spinner; later calls update the existing bar in place.
 */
export function renderProgress(root: HTMLElement, p: DownloadProgress): void {
  let bar = root.querySelector<HTMLElement>(".tab-progress");
  if (!bar) {
    bar = buildProgressBar();
    root.replaceChildren(bar);
  }
  const fill = bar.querySelector<HTMLElement>(".tab-progress-fill");
  const label = bar.querySelector<HTMLElement>(".tab-progress-label");
  if (p.phase === "resolving") {
    // No firm chunk total yet — show an indeterminate bar.
    bar.classList.add("is-indeterminate");
    if (fill) fill.style.width = "";
    if (label) label.textContent = "resolving…";
  } else {
    bar.classList.remove("is-indeterminate");
    const pct =
      p.total > 0 ? Math.min(100, Math.round((p.done / p.total) * 100)) : 0;
    if (fill) fill.style.width = `${pct}%`;
    if (label) label.textContent = `fetching ${pct}%`;
  }
}

function buildProgressBar(): HTMLElement {
  const wrap = document.createElement("div");
  wrap.className = "tab-progress";
  wrap.setAttribute("role", "progressbar");
  const track = document.createElement("div");
  track.className = "tab-progress-track";
  const fill = document.createElement("div");
  fill.className = "tab-progress-fill";
  track.appendChild(fill);
  const label = document.createElement("div");
  label.className = "tab-progress-label";
  wrap.append(track, label);
  return wrap;
}
