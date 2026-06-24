// Deterministic identity index (0-7) for an agent id. Shared by the avatar
// gradient and the message-bubble accent so a person's avatar and bubbles
// read as one identity hue.
export function identityIndex(agentId: string): number {
  const byte = Number.parseInt(agentId.slice(0, 2), 16);
  return Number.isFinite(byte) ? byte % 8 : 0;
}

// Deterministic warm-gradient class for an agent id avatar. The eight
// gradients are theme-invariant identity colors (same rationale as the
// QR export card's baked palette).
export function avatarGradientClass(agentId: string): string {
  return `chat-avatar--g${identityIndex(agentId)}`;
}

// Per-identity message-bubble accent class for a non-self sender, sharing the
// avatar's index (hue) so a person's avatar and bubbles match. Makes "who is
// who" scannable in a group at a glance without leaving the palette.
export function bubbleIdentityClass(agentId: string): string {
  return `chat-bubble--id${identityIndex(agentId)}`;
}

// Per-identity color class for a group sender-name label, sharing the avatar
// and bubble index (hue) so the name, avatar, and bubble stripe all read as the
// one identity.
export function senderIdentityClass(agentId: string): string {
  return `chat-sender--id${identityIndex(agentId)}`;
}

// Up-to-two-letter initials for an avatar fallback. Two words -> first letter
// of each; one word -> first two letters; empty -> "?". Shared by the
// conversation list and the header identity badge so every avatar derives its
// label the same way.
export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}
