import type { LookupResult } from "../fediverse/api";
import type { ProfileOutcome, ProfileLinkDto, ProfileAvatarMeta } from "../chat/types";

export interface ProfilePageModel {
  state: "verified" | "publicOnly" | "none" | "error";
  agentId: string | null;
  handle: string | null;
  display: string;
  verified: boolean;
  changedHands: boolean;
  verifyFailure: string | null;
  bio: string | null;
  website: string | null;
  avatar: ProfileAvatarMeta | null;
  links: ProfileLinkDto[];
  shareUri: string | null;
  isSelf: boolean;
  error: string | null;
}

export type ProfileInput =
  | { kind: "handle"; handle: string; relayHint?: string | null; isSelf?: boolean }
  | { kind: "agentId"; agentId: string; relayHint?: string | null; isSelf?: boolean; display?: string };

export interface ResolveDeps {
  lookupHandle: (handle: string) => Promise<LookupResult>;
  fetchProfile: (agentId: string, relay?: string | null) => Promise<ProfileOutcome>;
}

/** Pull the `?relay=` value out of a v3 share URI. `fetchit://` does not
 * parse as a WHATWG URL, so read the query by hand. */
export function relayFromShareUri(uri: string): string | null {
  const q = uri.indexOf("?");
  if (q < 0) return null;
  const params = new URLSearchParams(uri.slice(q + 1));
  return params.get("relay");
}

function empty(over: Partial<ProfilePageModel>): ProfilePageModel {
  return {
    state: "error", agentId: null, handle: null, display: "", verified: false,
    changedHands: false, verifyFailure: null, bio: null, website: null,
    avatar: null, links: [], shareUri: null, isSelf: false, error: null, ...over,
  };
}

export async function resolveProfile(input: ProfileInput, deps: ResolveDeps): Promise<ProfilePageModel> {
  if (input.kind === "handle") return resolveHandle(input, deps);
  return resolveAgentId(input, deps);
}

async function resolveHandle(
  input: Extract<ProfileInput, { kind: "handle" }>,
  deps: ResolveDeps,
): Promise<ProfilePageModel> {
  let look: LookupResult;
  try {
    look = await deps.lookupHandle(input.handle);
  } catch (e) {
    return empty({ handle: input.handle, display: input.handle, error: errText(e) });
  }
  const base = empty({
    handle: look.handle,
    display: look.displayName || look.handle,
    agentId: look.agentIdHex ?? null,
    bio: look.bio ?? null,
    avatar: look.avatar ?? null,
    shareUri: look.shareUri ?? null,
    verifyFailure: look.verifyFailure ?? null,
    changedHands: !!look.previousAgentIdHex,
    isSelf: !!input.isSelf,
  });
  if (look.kind !== "verified" || !look.agentIdHex) {
    return { ...base, state: "publicOnly", verified: false };
  }
  // Verified: enrich with the manifest (links/website). A manifest miss
  // degrades to identity-only, never an error (the binding already proved).
  const relay = input.relayHint ?? (look.shareUri ? relayFromShareUri(look.shareUri) : null);
  try {
    const out = await deps.fetchProfile(look.agentIdHex, relay);
    if (out.kind === "profile") {
      return { ...base, state: "verified", verified: true, website: out.website ?? null, links: out.links, bio: out.bio ?? base.bio, avatar: out.avatar ?? base.avatar };
    }
  } catch {
    /* identity-only */
  }
  return { ...base, state: "verified", verified: true };
}

async function resolveAgentId(
  input: Extract<ProfileInput, { kind: "agentId" }>,
  deps: ResolveDeps,
): Promise<ProfilePageModel> {
  let out: ProfileOutcome;
  try {
    out = await deps.fetchProfile(input.agentId, input.relayHint ?? null);
  } catch (e) {
    return empty({ agentId: input.agentId, display: input.display || short(input.agentId), isSelf: !!input.isSelf, error: errText(e) });
  }
  if (out.kind === "none") {
    return empty({ state: "none", agentId: input.agentId, display: input.display || short(input.agentId), isSelf: !!input.isSelf });
  }
  return empty({
    state: "verified", verified: true, agentId: input.agentId,
    display: out.displayName || input.display || short(input.agentId),
    bio: out.bio ?? null, website: out.website ?? null, links: out.links,
    avatar: out.avatar ?? null, isSelf: !!input.isSelf,
  });
}

function short(id: string): string {
  return `${id.slice(0, 6)}…${id.slice(-4)}`;
}
function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
