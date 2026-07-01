// The calm, persistent offline banner copy — the single grandma-grade
// reassurance shown when the chat service or relay link is not connected.
// Replaces the old alarming one-time "close and reopen Chat" toast: the
// connection auto-reconnects on a backoff and the engine outbox holds and
// resends queued messages, so the honest, calming truth is "your messages are
// saved and will send once you're back online."
//
// `connectionBannerCopy` is the source of truth for this vocabulary. Android
// mirrors the same strings so a person sees identical words across shells.

import type { DaemonStatus, RelayStatus } from "./state";

export type ConnectionTone = "info" | "warn";

export interface ConnectionBannerCopy {
  text: string;
  tone: ConnectionTone;
}

/// Map the live connection state onto the banner, or `null` when fully
/// connected (no banner). The local chat service is checked before the relay
/// link: nothing works without the service, so its state wins. A first-boot
/// `connecting` relay is deliberately silent — it is the normal startup path,
/// not an outage, so we never alarm the user before anything has gone wrong.
export function connectionBannerCopy(
  daemon: DaemonStatus | null,
  relay: RelayStatus | null,
): ConnectionBannerCopy | null {
  if (daemon === "down") {
    return {
      tone: "warn",
      text: "Chat service is offline. Your messages are saved and will send once it reconnects.",
    };
  }
  if (daemon === "reconnecting") {
    return { tone: "info", text: "Reconnecting to chat… your messages are saved." };
  }
  if (relay === "down") {
    return {
      tone: "warn",
      text: "No connection. Your messages are saved and will send once you're back online.",
    };
  }
  if (relay === "reconnecting") {
    return {
      tone: "info",
      text: "Reconnecting… your messages will send once you're back online.",
    };
  }
  return null;
}
