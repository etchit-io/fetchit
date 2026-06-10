// Wire the daemon's `fediverse:post` Tauri event stream into a mounted
// fediverse pane. The Rust event bridge (src-tauri) drains
// Client::subscribe_to_public_posts and emits one event per inbound
// bridged post; the pane renders it.

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { PublicPostDelivery } from "./feedPost";
import type { FediversePanelApi } from "./panel";

/// Wire-shape of the `fediverse:post` Tauri event. Mirrors the Rust
/// `PublicPostDelivery`; `activity_json` arrives as the raw JSON text.
export interface PublicPostEvent {
  verified_actor_url: string;
  activity_json: string;
}

/// Project the snake_case wire event into the camelCase delivery the
/// renderer consumes. Exported so the mapping is unit-testable without
/// a Tauri `listen` mock.
export function mapPublicPostEvent(ev: PublicPostEvent): PublicPostDelivery {
  return {
    verifiedActorUrl: ev.verified_actor_url,
    activityJson: ev.activity_json,
  };
}

/// Subscribe the pane's feed to the `fediverse:post` event stream.
/// Returns the unlisten handle; hold it for the panel's lifetime.
export async function bindFediverseEvents(
  panel: FediversePanelApi,
): Promise<UnlistenFn> {
  return listen<PublicPostEvent>("fediverse:post", (ev) => {
    panel.add(mapPublicPostEvent(ev.payload));
  });
}
