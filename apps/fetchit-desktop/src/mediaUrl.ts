import { invoke } from "@tauri-apps/api/core";

let cachedBase: string | null = null;

export async function initMediaBase(): Promise<string> {
  if (cachedBase !== null) return cachedBase;
  cachedBase = await invoke<string>("media_url_base");
  return cachedBase;
}

export function mediaUrlOf(addr: string): string {
  return `${mediaBase()}/${addr}`;
}

export function mediaBase(): string {
  if (cachedBase === null) {
    throw new Error("mediaUrl: call initMediaBase() before rendering media");
  }
  return cachedBase;
}

/** Test-only: skip the IPC roundtrip and set the base directly. */
export function setMediaBaseForTesting(base: string): void {
  cachedBase = base;
}
