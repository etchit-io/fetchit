// Thin wrappers over the Tauri commands exposed by `src-tauri/src/chat.rs`.
// Functions return the daemon-shaped types from `./types`. All errors
// bubble as `Error` instances with the daemon's text message.

import { invoke } from "@tauri-apps/api/core";
import type {
  AgentIdentity,
  CardWithUri,
  Contact,
  Group,
  GroupMessage,
  OnlineAgent,
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

export async function sendDm(
  to: string,
  body: string,
  senderName?: string,
): Promise<string | null> {
  return invoke<string | null>("chat_send_dm", {
    to,
    body,
    senderName: senderName ?? null,
  });
}

export async function dmConnect(agentId: string): Promise<void> {
  await invoke("chat_dm_connect", { agentId });
}

export async function presenceOnline(): Promise<OnlineAgent[]> {
  return invoke<OnlineAgent[]>("chat_presence_online");
}

export async function listGroups(): Promise<Group[]> {
  return invoke<Group[]>("chat_groups_list");
}

export async function createGroup(
  name: string,
  displayName?: string,
): Promise<Group> {
  return invoke<Group>("chat_group_create", {
    name,
    displayName: displayName ?? null,
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
