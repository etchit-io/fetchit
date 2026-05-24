// Forwards backend `download-progress` events to the live mascot in
// the matching tab. The mascot itself owns the visualization — this
// module is just the bridge between the Tauri event channel and the
// per-tab controller.

import { listen } from "@tauri-apps/api/event";
import type { TabStore } from "../tabs";
import { findMascotIn } from "./mascot";

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
 * Subscribe to backend progress events and forward each one to the
 * mascot mounted in the matching tab. The backend emits these only
 * when the on-disk cache is enabled — with the cache off no events
 * arrive and the mascot simply stays in its `idle-running` state.
 */
export function mountDownloadProgress(store: TabStore): void {
  void listen<DownloadProgress>("download-progress", ({ payload }) => {
    const want = payload.address.toLowerCase();
    const tab = store
      .list()
      .find((t) => t.status === "loading" && t.address?.toLowerCase() === want);
    if (!tab) return;
    findMascotIn(tab.root)?.applyProgress(payload);
  });
}
