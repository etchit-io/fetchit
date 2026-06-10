// TypeScript mirror of the `fetchit-chat` Rust types. Keep in sync
// with `crates/fetchit-chat/src/{contacts,identity,messages,presence,
// groups,events}.rs`.

export type AgentId = string;
export type GroupIdStr = string;

export type TrustLevel = "blocked" | "unknown" | "known" | "trusted";

export interface AgentIdentity {
  agent_id: AgentId;
  machine_id: string;
  user_id?: string | null;
  kem_public_key_b64?: string | null;
}

export interface AgentCard {
  agent_id: AgentId;
  display_name: string;
  created_at?: number | null;
  addresses?: string[];
  [extra: string]: unknown;
}

export interface CardWithUri {
  card: AgentCard;
  uri: string;
}

export interface Contact {
  agent_id: AgentId;
  label?: string | null;
  display_name?: string | null;
  trust_level: TrustLevel;
  added_at?: number | null;
  last_seen?: number | null;
}

export interface DirectMessage {
  from: AgentId;
  to?: AgentId | null;
  body: string;
  sender_name?: string | null;
  timestamp_ms?: number | null;
  message_id?: string | null;
  reply_to_message_id?: string | null;
  verified?: boolean | null;
}

export interface PresenceTransition {
  agent_id: AgentId;
  event: "online" | "offline" | string;
  reachable?: boolean | null;
}

export interface OnlineAgent {
  agent_id: AgentId;
  machine_id?: string | null;
  user_id?: string | null;
  addresses?: string[];
  last_seen?: number | null;
  announced_at?: number | null;
}

export interface Group {
  group_id: GroupIdStr;
  name?: string | null;
  member_count?: number;
  is_owner?: boolean;
}

export interface GroupMessage {
  group_id: GroupIdStr;
  from: AgentId;
  body: string;
  timestamp_ms: number;
  kind: string;
  message_id: string;
}

// Discriminated union mirroring `fetchit_chat::events::Event`.
export type ChatEvent =
  | ({ kind: "direct_message" } & DirectMessage)
  | ({ kind: "presence" } & PresenceTransition)
  | ({ kind: "contact_added" } & Contact)
  | { kind: "contact_removed"; agent_id: AgentId }
  | {
      kind: "gossip_message";
      topic: string;
      payload: number[];
      from: AgentId | null;
    }
  | { kind: "other"; event_name: string; data: unknown };
