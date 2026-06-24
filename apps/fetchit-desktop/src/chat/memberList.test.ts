import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";
import { ChatStore } from "./state";
import type { Contact } from "./types";
import { mountMemberList, memberDisplayName } from "./memberList";

const ME = "a".repeat(64);
const BOB = "b".repeat(64);

function makeStore(): ChatStore {
  const s = new ChatStore();
  s.setIdentity({ agent_id: ME, machine_id: "m" });
  return s;
}

describe("memberDisplayName", () => {
  it("prefers the name the member joined with", () => {
    expect(memberDisplayName(makeStore(), BOB, "Joined Bob")).toBe("Joined Bob");
  });

  it("falls back to a saved-contact label", () => {
    const s = makeStore();
    s.upsertContact({ agent_id: BOB, label: "Mum" } as Contact);
    expect(memberDisplayName(s, BOB)).toBe("Mum");
  });

  it("falls back to a short id when nothing resolves", () => {
    expect(memberDisplayName(makeStore(), "cd".repeat(32))).toBe("cdcdcdcd…");
  });
});

describe("mountMemberList", () => {
  let host: HTMLElement;
  beforeEach(() => {
    localStorage.clear();
    host = document.createElement("div");
    document.body.appendChild(host);
  });
  afterEach(() => {
    host.remove();
    vi.mocked(invoke).mockReset();
  });

  it("lists each member by name and tags the user as (you)", async () => {
    vi.mocked(invoke).mockResolvedValue([
      { agent_id: ME, display_name: "Me" },
      { agent_id: BOB, display_name: "Bob" },
    ]);
    mountMemberList(host, {
      groupId: "g1", groupTitle: "Book Club", store: makeStore(), onClose: () => {},
    });
    await vi.waitFor(() =>
      expect(host.querySelectorAll(".chat-member").length).toBe(2),
    );
    const names = [...host.querySelectorAll(".chat-member__name")].map(
      (n) => n.textContent,
    );
    expect(names).toContain("Me (you)");
    expect(names).toContain("Bob");
    // Count is folded into the title.
    expect(host.querySelector("h3")?.textContent).toContain("2");
  });

  it("shows an error line when the roster fails to load", async () => {
    vi.mocked(invoke).mockRejectedValue("relay returned 500");
    mountMemberList(host, {
      groupId: "g1", groupTitle: "Book Club", store: makeStore(), onClose: () => {},
    });
    await vi.waitFor(() =>
      expect(host.querySelector(".chat-dialog__status")?.textContent).toContain(
        "Couldn't load members",
      ),
    );
  });

  it("close button invokes onClose", () => {
    vi.mocked(invoke).mockResolvedValue([]);
    const onClose = vi.fn();
    mountMemberList(host, {
      groupId: "g1", groupTitle: "Book Club", store: makeStore(), onClose,
    });
    host.querySelector<HTMLButtonElement>(".chat-dialog__btn--ghost")!.click();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
