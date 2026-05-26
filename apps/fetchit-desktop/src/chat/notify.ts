// OS-toast notifications for inbound DMs. Skips when the window has
// focus or when the message is the user's own echo. Permission is
// requested on first need; if the user declines we never re-ask.

import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { ChatStore } from "./state";
import type { DirectMessage } from "./types";

let cachedPermission: "granted" | "denied" | "default" = "default";
let inflight: Promise<void> | null = null;

const TITLE = "fetch>it · DM";

async function windowIsFocused(): Promise<boolean> {
  try {
    return await getCurrentWindow().isFocused();
  } catch (e) {
    // Outside Tauri (tests) — fall back to the DOM check.
    return typeof document !== "undefined" && document.hasFocus();
  }
}

export async function maybeNotifyInboundDm(
  store: ChatStore,
  dm: DirectMessage,
): Promise<void> {
  if (!dm.body || dm.body.trim().length === 0) {
    console.log("[chat][notify] skip: empty body");
    return;
  }
  if (dm.from === store.myId()) {
    console.log("[chat][notify] skip: own echo");
    return;
  }
  const focused = await windowIsFocused();
  if (focused) {
    console.log("[chat][notify] skip: window focused");
    return;
  }

  await ensurePermission();
  console.log("[chat][notify] permission:", cachedPermission);
  if (cachedPermission !== "granted") return;

  const sender = senderLabel(store, dm);
  const body = dm.body.length > 140 ? `${dm.body.slice(0, 137)}…` : dm.body;
  try {
    sendNotification({
      title: TITLE,
      body: `${sender}: ${body}`,
    });
    console.log("[chat][notify] sent:", sender, "→", body);
  } catch (e) {
    console.warn("[chat][notify] failed:", e);
  }
}

async function ensurePermission(): Promise<void> {
  if (cachedPermission !== "default") return;
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      const already = await isPermissionGranted();
      console.log("[chat][notify] isPermissionGranted:", already);
      if (already) {
        cachedPermission = "granted";
        return;
      }
      const result = await requestPermission();
      console.log("[chat][notify] requestPermission ->", result);
      cachedPermission = result === "granted" ? "granted" : "denied";
    } catch (e) {
      console.warn("[chat][notify] permission probe failed:", e);
      cachedPermission = "denied";
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

function senderLabel(store: ChatStore, dm: DirectMessage): string {
  if (dm.sender_name && dm.sender_name.trim().length > 0) return dm.sender_name;
  const c = store.contact(dm.from);
  return c?.label ?? c?.display_name ?? `${dm.from.slice(0, 8)}…`;
}

// Exposed for tests — clears the cached permission state so a fresh
// run starts from `default`.
export function _resetNotifyState(): void {
  cachedPermission = "default";
  inflight = null;
}
