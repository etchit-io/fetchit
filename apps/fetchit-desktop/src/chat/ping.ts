// A short "ping" tone generated on the fly via Web Audio — no
// external asset needed, no autoplay-policy interference because the
// AudioContext is created lazily on the first user interaction with
// the running app (which has already happened by the time a DM
// arrives, otherwise the chat panel couldn't have been opened).

let ctx: AudioContext | null = null;

function ensureCtx(): AudioContext | null {
  if (ctx) return ctx;
  if (typeof window === "undefined") return null;
  const AC = window.AudioContext;
  if (!AC) return null;
  try {
    ctx = new AC();
  } catch (e) {
    console.warn("[chat] AudioContext unavailable:", e);
    return null;
  }
  return ctx;
}

/// Two-note descending ping — short, distinct from system sounds,
/// audible without being startling. Safe to call rapidly; each call
/// is a separate oscillator that auto-disposes after ~0.4s.
export function playInboundPing(): void {
  const ac = ensureCtx();
  if (!ac) return;
  const now = ac.currentTime;
  // Resume the context in case the browser auto-suspended it.
  if (ac.state === "suspended") {
    void ac.resume().catch(() => {});
  }
  pingTone(ac, now, 880, 0.0, 0.18);
  pingTone(ac, now + 0.12, 660, 0.0, 0.18);
}

function pingTone(
  ac: AudioContext,
  start: number,
  freq: number,
  delay: number,
  duration: number,
): void {
  const osc = ac.createOscillator();
  const gain = ac.createGain();
  osc.connect(gain);
  gain.connect(ac.destination);
  osc.type = "sine";
  osc.frequency.value = freq;
  gain.gain.setValueAtTime(0.0001, start + delay);
  gain.gain.exponentialRampToValueAtTime(0.18, start + delay + 0.01);
  gain.gain.exponentialRampToValueAtTime(0.0001, start + delay + duration);
  osc.start(start + delay);
  osc.stop(start + delay + duration + 0.02);
}
