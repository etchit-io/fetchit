// Typed wrappers for the M5 fediverse commands. Mirrors chat/api.ts:
// thin invoke passthroughs; the Rust commands stringify their own
// errors, so rejected promises carry user-facing messages.

import { invoke } from "@tauri-apps/api/core";

export interface LookupAvatar {
  addr: string;
  mime: string;
  w: number;
  h: number;
  bytesLen: number;
}

/// Flat lookup result from `fediverse_lookup`. `kind` discriminates:
/// "verified" carries the private-bootstrap fields, "publicOnly" only
/// the public identity pair (+ an optional visible verify failure).
export interface LookupResult {
  kind: "verified" | "publicOnly";
  handle: string;
  actorUrl: string;
  agentIdHex?: string | null;
  displayName?: string | null;
  bio?: string | null;
  avatar?: LookupAvatar | null;
  shareUri?: string | null;
  previousAgentIdHex?: string | null;
  verifyFailure?: string | null;
}

export async function lookupHandle(handle: string): Promise<LookupResult> {
  return invoke<LookupResult>("fediverse_lookup", { handle });
}

export interface MintOutcome {
  actorUrl: string;
  registered: boolean;
  registrationError: string | null;
}

export async function mintActor(handle: string): Promise<MintOutcome> {
  return invoke<MintOutcome>("fediverse_mint", { handle });
}

export interface EnsureV2Outcome {
  upgraded: boolean;
  registered: boolean;
  pending: string | null;
}

export async function ensureV2(): Promise<EnsureV2Outcome> {
  return invoke<EnsureV2Outcome>("fediverse_ensure_v2");
}
