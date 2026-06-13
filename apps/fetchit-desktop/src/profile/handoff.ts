import { invoke } from "@tauri-apps/api/core";

export async function probeEtchit(): Promise<{ installed: boolean }> {
  return invoke<{ installed: boolean }>("etchit_handoff");
}
export async function openEtchitProfile(): Promise<void> {
  await invoke("etchit_open_profile");
}
