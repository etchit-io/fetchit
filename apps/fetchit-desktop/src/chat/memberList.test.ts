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

describe("member moderation", () => {
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

  const CAROL = "c".repeat(64);

  async function confirmRemove(): Promise<void> {
    const ok = [
      ...document.querySelectorAll<HTMLButtonElement>(
        ".chat-dialog:not([hidden]) .chat-dialog__btn",
      ),
    ].find((b) => !b.classList.contains("chat-dialog__btn--ghost"));
    ok!.click();
    await Promise.resolve();
    await Promise.resolve();
  }

  function mount(roster: unknown[]): void {
    vi.mocked(invoke).mockImplementation((cmd: string) =>
      cmd === "chat_group_members"
        ? Promise.resolve(roster)
        : Promise.resolve(),
    );
    mountMemberList(host, {
      groupId: "g1", groupTitle: "G", store: makeStore(), onClose: () => {},
    });
  }

  it("an owner can remove a non-owner member, dropping the row", async () => {
    mount([
      { agent_id: ME, display_name: "Me", role: "owner" },
      { agent_id: BOB, display_name: "Bob", role: "member" },
    ]);
    await vi.waitFor(() =>
      expect(host.querySelectorAll(".chat-member").length).toBe(2),
    );
    const remove = host.querySelector<HTMLButtonElement>(".chat-member__remove");
    expect(remove).not.toBeNull();
    remove!.click();
    await confirmRemove();
    expect(vi.mocked(invoke)).toHaveBeenCalledWith("chat_group_remove_member", {
      groupId: "g1", agentId: BOB,
    });
    expect(host.querySelectorAll(".chat-member").length).toBe(1);
  });

  it("a plain member sees no remove controls", async () => {
    mount([
      { agent_id: ME, display_name: "Me", role: "member" },
      { agent_id: BOB, display_name: "Bob", role: "member" },
    ]);
    await vi.waitFor(() =>
      expect(host.querySelectorAll(".chat-member").length).toBe(2),
    );
    expect(host.querySelector(".chat-member__remove")).toBeNull();
  });

  it("never offers remove on another owner or on self, and tags owners", async () => {
    mount([
      { agent_id: ME, display_name: "Me", role: "owner" },
      { agent_id: CAROL, display_name: "Carol", role: "owner" },
    ]);
    await vi.waitFor(() =>
      expect(host.querySelectorAll(".chat-member").length).toBe(2),
    );
    expect(host.querySelectorAll(".chat-member__role").length).toBe(2);
    expect(host.querySelector(".chat-member__remove")).toBeNull();
  });

  it("an owner can ban a non-owner member, dropping the row", async () => {
    mount([
      { agent_id: ME, display_name: "Me", role: "owner" },
      { agent_id: BOB, display_name: "Bob", role: "member" },
    ]);
    await vi.waitFor(() =>
      expect(host.querySelectorAll(".chat-member").length).toBe(2),
    );
    const ban = host.querySelector<HTMLButtonElement>(".chat-member__ban");
    expect(ban).not.toBeNull();
    ban!.click();
    await confirmRemove();
    expect(vi.mocked(invoke)).toHaveBeenCalledWith("chat_group_ban_member", {
      groupId: "g1", agentId: BOB,
    });
    expect(host.querySelectorAll(".chat-member").length).toBe(1);
  });

  it("an owner can rename the group from the title", async () => {
    const onChanged = vi.fn();
    vi.mocked(invoke).mockImplementation((cmd: string) =>
      cmd === "chat_group_members"
        ? Promise.resolve([{ agent_id: ME, display_name: "Me", role: "owner" }])
        : Promise.resolve(),
    );
    mountMemberList(host, {
      groupId: "g1", groupTitle: "Old", store: makeStore(), onClose: () => {}, onChanged,
    });
    await vi.waitFor(() =>
      expect(host.querySelector(".chat-members__title--editable")).not.toBeNull(),
    );
    host.querySelector<HTMLElement>(".chat-members__title--editable")!.click();
    const input = host.querySelector<HTMLInputElement>(".chat-members__rename")!;
    expect(input.value).toBe("Old");
    input.value = "New Name";
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
    await vi.waitFor(() =>
      expect(vi.mocked(invoke)).toHaveBeenCalledWith("chat_group_rename", {
        groupId: "g1", name: "New Name",
      }),
    );
    await vi.waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it("a plain member cannot rename (title not editable)", async () => {
    mount([{ agent_id: ME, display_name: "Me", role: "member" }]);
    await vi.waitFor(() =>
      expect(host.querySelectorAll(".chat-member").length).toBe(1),
    );
    expect(host.querySelector(".chat-members__title--editable")).toBeNull();
  });
});
