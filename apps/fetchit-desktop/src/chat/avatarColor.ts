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
