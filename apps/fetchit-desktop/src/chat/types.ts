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

/// An inline image attachment carried inside a sealed message payload.
/// Mirrors `fetchit_chat::attachment::Attachment` (the wire type Bob's
/// lane validates on both send and receive). `bytes_b64` is standard
/// base64 (no line wrapping) of the raw image bytes. Raster only — the
/// backend rejects `image/svg+xml` because SVG can carry script.
export interface Attachment {
  mime: string;
  width: number;
  height: number;
  bytes_b64: string;
}

export interface DirectMessage {
  from: AgentId;
  to?: AgentId | null;
  body: string;
  sender_name?: string | null;
  timestamp_ms?: number | null;
  message_id?: string | null;
  reply_to_message_id?: string | null;
  /// Optional inline image. On receive it is validated by `fetchit-chat`
  /// (oversize / non-raster / bad-base64 stripped to null before it
  /// reaches the UI); on send the desktop sniffs the bytes at attach
  /// time. It always renders through an `<img>` data-URL built from the
  /// validated raster MIME, so the bytes decode as that image format and
  /// can never execute as markup.
  attachment?: Attachment | null;
  verified?: boolean | null;
}

/// One outbound-DM outbox change, emitted by the backend `chat:outbox`
/// pump (one per `fetchit_chat::outbox::OutboxEvent`) and replayed by
/// the `chat_outbox_snapshot` command on open. Serialized straight from
/// the engine `OutboxBubble`, so the field names are snake_case and the
/// status is the engine enum's variant name; `ChatStore.applyOutboxEvent`
/// projects it onto the camelCase `ChatBubble`. The engine owns the
/// send/retry/delivery lifecycle, so this is the desktop's only source
/// of truth for outbound bubble *status* (the reply quote and attachment
/// it cannot carry are supplied shell-side -- see `stageOutboundMeta`).
export interface OutboxBubbleDto {
  id: string;
  peer: AgentId;
  body: string;
  status: "Sending" | "Delivered" | "Failed";
  message_id?: string | null;
  enqueued_at_ms: number;
  last_error?: string | null;
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

/// One private-group message. Two producers share this shape:
/// the daemon history poll (`chat_group_messages` -> `groupHistory`,
/// which always sets `kind` via the Rust `default_kind`) and the live
/// inbound decrypt pump (`chat:group-message`, which omits `kind` and
/// carries `sender_name` / `attachment` from the decoded `HistoryEntry`).
/// Both optional-only fields are absent on the path that doesn't set them.
export interface GroupMessage {
  group_id: GroupIdStr;
  from: AgentId;
  body: string;
  timestamp_ms: number;
  message_id: string;
  /// Daemon-history message class (`chat`, `system`, …). Present only on
  /// the history-poll path; the live `chat:group-message` event omits it.
  kind?: string;
  /// Sender display name at send time. Carried by the live decrypt path.
  sender_name?: string | null;
  /// Inline image attachment, validated by `fetchit-chat` before it
  /// reaches the UI. Carried by the live decrypt path.
  attachment?: Attachment | null;
}

/// The `chat:group-message` Tauri event payload is a `GroupMessage` whose
/// `kind` is absent (the live decrypt path doesn't set a message class).
export type GroupMessageEvent = GroupMessage;

export interface ProfileAvatarMeta {
  addr: string;
  mime: string;
  w: number;
  h: number;
  bytesLen: number;
}

export interface ProfileLinkDto {
  kind: string;
  label: string;
  addr: string;
}

export interface ProfileDto {
  displayName: string;
  bio?: string | null;
  website?: string | null;
  links: ProfileLinkDto[];
  avatar?: ProfileAvatarMeta | null;
  issuedAtMs: number;
}

export type ProfileOutcome =
  | ({ kind: "profile" } & ProfileDto)
  | { kind: "none" };

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
