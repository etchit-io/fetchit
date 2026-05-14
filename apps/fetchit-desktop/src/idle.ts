// JS-side idle tracker. Watches user-interaction events; when nothing happens
// for `timeoutMinutes`, fires the `idle_disconnect` Rust command which drops
// the Autonomi client connection, clears the in-memory cache, and (if the
// disk-cache policy is `OnIdle`) wipes the on-disk cache too.
//
// `timeoutMinutes === 0` disables the timer entirely.

import { invoke } from "@tauri-apps/api/core";

const ACTIVITY_EVENTS = ["mousemove", "keydown", "wheel", "touchstart", "click"] as const;

export interface IdleTracker {
  /** Update the timeout in minutes (0 disables). Resets the timer. */
  setTimeoutMinutes(minutes: number): void;
  /** Manually mark activity (e.g. on every fetch the controller starts). */
  bump(): void;
  /** Stop tracking — removes listeners and cancels any pending timer. */
  destroy(): void;
}

export function startIdleTracker(): IdleTracker {
  let timeoutMs = 0;
  let timer: number | null = null;

  const onIdle = (): void => {
    timer = null;
    void invoke("idle_disconnect").catch(() => {});
  };

  const bump = (): void => {
    if (timer !== null) {
      window.clearTimeout(timer);
      timer = null;
    }
    if (timeoutMs > 0) timer = window.setTimeout(onIdle, timeoutMs);
  };

  const handler = (): void => bump();
  for (const e of ACTIVITY_EVENTS) {
    document.addEventListener(e, handler, { passive: true });
  }

  return {
    setTimeoutMinutes(minutes) {
      timeoutMs = Math.max(0, Math.floor(minutes)) * 60 * 1000;
      bump();
    },
    bump,
    destroy() {
      for (const e of ACTIVITY_EVENTS) document.removeEventListener(e, handler);
      if (timer !== null) window.clearTimeout(timer);
      timer = null;
    },
  };
}
