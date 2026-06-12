// Deterministic warm-gradient class for an agent id avatar. The eight
// gradients are theme-invariant identity colors (same rationale as the
// QR export card's baked palette).
export function avatarGradientClass(agentId: string): string {
  const byte = Number.parseInt(agentId.slice(0, 2), 16);
  const idx = Number.isFinite(byte) ? byte % 8 : 0;
  return `chat-avatar--g${idx}`;
}
