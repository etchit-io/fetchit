// Thin wrappers over the Tauri commands exposed by `src-tauri/src/chat.rs`.
// Functions return the daemon-shaped types from `./types`. All errors
// bubble as `Error` instances with the daemon's text message.

import { invoke } from "@tauri-apps/api/core";
import type {
  AgentIdentity,
  Attachment,
  CardWithUri,
  Contact,
  Group,
  GroupMessage,
  OnlineAgent,
  ProfileOutcome,
  TrustLevel,
} from "./types";

export async function health(): Promise<boolean> {
  return invoke<boolean>("chat_health");
}

export async function identity(): Promise<AgentIdentity> {
  return invoke<AgentIdentity>("chat_identity");
}

export async function myCard(displayName: string): Promise<CardWithUri> {
  return invoke<CardWithUri>("chat_card", { displayName });
}

export async function importCard(uri: string): Promise<void> {
  await invoke("chat_import_card", { uri });
}

/// Flip a TOFU welcome from `TrustState::Pending` to `Confirmed`.
/// Called from the pending-contacts dialog after the user clicks
/// Accept on a first-contact request.
export async function confirmContact(groupIdHex: string): Promise<void> {
  await invoke("chat_confirm_contact", { groupIdHex });
}

export interface PairAccepted {
  agentIdHex: string;
  /// Offerer's relay URL as embedded in their v3 share URI. The
  /// frontend renders this in the cross-relay warning so the user
  /// can see exactly which relay to switch to.
  offererRelayUrl: string;
  /// True when the offerer's published relay differs from the
  /// local user's. Until cross-relay federation lands, peers on
  /// different relays can't exchange messages — the panel surfaces
  /// a notice when this is set.
  crossRelay: boolean;
}

/// Accept a v3 share URI (`fetchit://share/v3/…`) by fetching the
/// offerer's profile-index record from the embedded relay, verifying
/// the ML-DSA-65 signature, and persisting a `StoredContactCard`
/// locally. The returned `agentIdHex` lets the caller navigate to
/// the new DM.
export async function pairAccept(uri: string): Promise<PairAccepted> {
  return invoke<PairAccepted>("chat_pair_accept", { uri });
}

/// Build a v3 share URI for the local identity by looking up its own
/// profile-index record on the relay. Rejects with a 'Publish your
/// profile first…' message when the relay has no record yet.
export async function pairShare(): Promise<string> {
  return invoke<string>("chat_pair_share");
}

export async function listContacts(): Promise<Contact[]> {
  return invoke<Contact[]>("chat_contacts");
}

export async function setTrust(
  agentId: string,
  level: TrustLevel,
): Promise<void> {
  await invoke("chat_set_trust", { agentId, level });
}

export async function removeContact(agentId: string): Promise<void> {
  await invoke("chat_remove_contact", { agentId });
}

/// Upper bound on one chat_send_dm round trip. The Rust side already
/// bounds the WS write (5s) and the relay ack wait (10s); this catches
/// the pathological cases those can't — a wedged invoke or a backend
/// path that never resolves — so the bubble fails honestly instead of
/// sitting in "sending" until the 24h sweep.
export const SEND_DM_TIMEOUT_MS = 30_000;

export async function sendDm(
  to: string,
  body: string,
  senderName?: string,
  replyToMessageId?: string | null,
  attachment?: Attachment | null,
): Promise<string | null> {
  const send = invoke<string | null>("chat_send_dm", {
    to,
    body,
    senderName: senderName ?? null,
    replyToMessageId: replyToMessageId ?? null,
    attachment: attachment ?? null,
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error("send timed out after 30s"));
    }, SEND_DM_TIMEOUT_MS);
  });
  try {
    return await Promise.race([send, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export async function dmConnect(agentId: string): Promise<void> {
  await invoke("chat_dm_connect", { agentId });
}

export async function presenceOnline(): Promise<OnlineAgent[]> {
  return invoke<OnlineAgent[]>("chat_presence_online");
}

export async function watchPresence(agentIds: string[]): Promise<void> {
  await invoke("chat_watch_presence", { agentIds });
}

export async function unwatchPresence(agentIds: string[]): Promise<void> {
  await invoke("chat_unwatch_presence", { agentIds });
}

export async function listGroups(): Promise<Group[]> {
  return invoke<Group[]>("chat_groups_list");
}

/// Which create-group surface to invoke on the daemon.
///
/// `"private_secure"` routes to `groups::create_private` (PQ-encrypted x0x
/// MLS, Hidden visibility); `"public_open"` routes to the legacy
/// `groups::create` (plaintext on relay). The frontend dialog defaults to
/// `"private_secure"`.
export type CreateGroupPreset = "private_secure" | "public_open";

export async function createGroup(
  name: string,
  displayName: string | undefined,
  preset: CreateGroupPreset,
): Promise<Group> {
  return invoke<Group>("chat_group_create", {
    name,
    displayName: displayName ?? null,
    preset,
  });
}

export async function groupInvite(groupId: string): Promise<string> {
  return invoke<string>("chat_group_invite", { groupId });
}

export async function joinGroup(
  invite: string,
  displayName?: string,
): Promise<Group> {
  return invoke<Group>("chat_group_join", {
    invite,
    displayName: displayName ?? null,
  });
}

export async function sendGroupMessage(
  groupId: string,
  body: string,
): Promise<string | null> {
  return invoke<string | null>("chat_group_send", { groupId, body });
}

export async function groupHistory(groupId: string): Promise<GroupMessage[]> {
  return invoke<GroupMessage[]>("chat_group_messages", { groupId });
}

export async function leaveGroup(groupId: string): Promise<void> {
  await invoke("chat_group_leave", { groupId });
}

export async function fetchProfile(agentId: string): Promise<ProfileOutcome> {
  return invoke<ProfileOutcome>("chat_fetch_profile", { agentId });
}

export async function fetchAvatar(
  addr: string,
  mime: string,
  bytesLen: number,
): Promise<string> {
  return invoke<string>("chat_fetch_avatar", { addr, mime, bytesLen });
}

export async function getDisplayName(): Promise<string> {
  return invoke<string>("display_name");
}

export async function setDisplayName(name: string): Promise<void> {
  await invoke("set_display_name", { name });
}
