import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { mountLookup } from "./lookup";

type InvokeMock = ReturnType<typeof vi.fn>;
const mock = invoke as InvokeMock;

const AGENT = "a".repeat(64);

const VERIFIED = {
  kind: "verified",
  handle: "@josh@etchit.io",
  actorUrl: "https://etchit.io/actors/josh",
  agentIdHex: AGENT,
  displayName: "Josh",
  bio: null,
  avatar: null,
  shareUri: `fetchit://share/v3/${AGENT}/${"b".repeat(64)}?relay=https%3A%2F%2Frelay.example%2F`,
  previousAgentIdHex: null,
  verifyFailure: null,
};

const PUBLIC_ONLY = {
  kind: "publicOnly",
  handle: "@gargron@mastodon.social",
  actorUrl: "https://mastodon.social/users/Gargron",
  verifyFailure: null,
};

function search(host: HTMLElement, text: string): void {
  const input = host.querySelector<HTMLInputElement>(".fediverse-lookup__input")!;
  input.value = text;
  host.querySelector<HTMLButtonElement>(".fediverse-lookup__btn")!.click();
}

let host: HTMLElement;
let opened: string[];

beforeEach(() => {
  mock.mockReset();
  document.body.innerHTML = "";
  host = document.createElement("div");
  document.body.appendChild(host);
  opened = [];
  mountLookup(host, { onOpenDm: (id) => opened.push(id), onViewProfile: () => {} });
});

describe("mountLookup", () => {
  it("rejects a non-handle input with inline copy, no invoke", () => {
    search(host, "not a handle");
    expect(host.querySelector(".fediverse-lookup__error")).not.toBeNull();
    expect(mock).not.toHaveBeenCalled();
  });

  it("renders a verified actor card with private affordances", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup" ? Promise.resolve(VERIFIED) : Promise.resolve(null),
    );
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card--verified")).not.toBeNull();
    });
    expect(host.querySelector(".actor-card__msg-btn")).not.toBeNull();
    expect(host.querySelector(".actor-card__invite-btn")).not.toBeNull();
    expect(host.textContent).toContain("Josh");
    expect(host.textContent).toContain("Verified fetch>it identity");
  });

  it("renders a public-only card without private affordances", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup" ? Promise.resolve(PUBLIC_ONLY) : Promise.resolve(null),
    );
    search(host, "@gargron@mastodon.social");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card--public")).not.toBeNull();
    });
    expect(host.querySelector(".actor-card__msg-btn")).toBeNull();
    expect(host.querySelector(".actor-card__invite-btn")).toBeNull();
  });

  it("shows the could-not-verify state on a failed attestation", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup"
        ? Promise.resolve({ ...PUBLIC_ONLY, verifyFailure: "signature does not verify" })
        : Promise.resolve(null),
    );
    search(host, "@evil@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__warn")).not.toBeNull();
    });
    expect(host.textContent).toContain("Couldn't verify");
    expect(host.querySelector(".actor-card__msg-btn")).toBeNull();
  });

  it("surfaces handle-changed-hands on the verified card", async () => {
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_lookup"
        ? Promise.resolve({ ...VERIFIED, previousAgentIdHex: "c".repeat(64) })
        : Promise.resolve(null),
    );
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__warn")).not.toBeNull();
    });
    expect(host.textContent).toContain("changed hands");
    // Changed hands is a warning, not a block: affordances stay.
    expect(host.querySelector(".actor-card__msg-btn")).not.toBeNull();
  });

  it("message-privately imports via chat_pair_accept then opens the DM", async () => {
    mock.mockImplementation((cmd: string) => {
      if (cmd === "fediverse_lookup") return Promise.resolve(VERIFIED);
      if (cmd === "chat_pair_accept")
        return Promise.resolve({
          agentIdHex: AGENT,
          offererRelayUrl: "https://relay.example/",
          crossRelay: false,
        });
      return Promise.resolve(null);
    });
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__msg-btn")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__msg-btn")!.click();
    await vi.waitFor(() => {
      expect(opened).toEqual([AGENT]);
    });
    const accept = mock.mock.calls.find((c) => c[0] === "chat_pair_accept")!;
    expect(accept[1]).toEqual({ uri: VERIFIED.shareUri });
  });

  it("invite-to-group sends the invite URI as a DM", async () => {
    mock.mockImplementation((cmd: string) => {
      if (cmd === "fediverse_lookup") return Promise.resolve(VERIFIED);
      if (cmd === "chat_pair_accept")
        return Promise.resolve({
          agentIdHex: AGENT,
          offererRelayUrl: "https://relay.example/",
          crossRelay: false,
        });
      if (cmd === "chat_groups_list")
        return Promise.resolve([{ group_id: "g1", name: "rust club" }]);
      if (cmd === "chat_group_invite") return Promise.resolve("x0x://invite/abc");
      if (cmd === "chat_send_dm") return Promise.resolve("msg-1");
      return Promise.resolve(null);
    });
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__invite-btn")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__invite-btn")!.click();
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__invite-send")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__invite-send")!.click();
    await vi.waitFor(() => {
      expect(mock.mock.calls.some((c) => c[0] === "chat_send_dm")).toBe(true);
    });
    const dm = mock.mock.calls.find((c) => c[0] === "chat_send_dm")!;
    expect(dm[1].to).toBe(AGENT);
    expect(dm[1].body).toContain("x0x://invite/abc");
    expect(dm[1].body).toContain("rust club");
    await vi.waitFor(() => {
      expect(host.textContent).toContain("Invite sent.");
    });
  });

  it("offers no invite flow when the user has no groups", async () => {
    mock.mockImplementation((cmd: string) => {
      if (cmd === "fediverse_lookup") return Promise.resolve(VERIFIED);
      if (cmd === "chat_groups_list") return Promise.resolve([]);
      return Promise.resolve(null);
    });
    search(host, "@josh@etchit.io");
    await vi.waitFor(() => {
      expect(host.querySelector(".actor-card__invite-btn")).not.toBeNull();
    });
    host.querySelector<HTMLButtonElement>(".actor-card__invite-btn")!.click();
    await vi.waitFor(() => {
      expect(host.textContent).toContain("No groups yet");
    });
    expect(host.querySelector(".actor-card__invite-send")).toBeNull();
  });

  it("renders an error state when lookup rejects", async () => {
    mock.mockImplementation(() => Promise.reject(new Error("couldn't resolve")));
    search(host, "@nobody@nowhere.example");
    await vi.waitFor(() => {
      expect(host.querySelector(".fediverse-lookup__error")).not.toBeNull();
    });
    expect(host.textContent).toContain("couldn't resolve");
  });
});

import { renderActorCard } from "./lookup";

describe("renderActorCard view profile", () => {
  it("offers View profile and routes the handle", () => {
    let seen: string | null = null;
    const dto = {
      kind: "verified" as const,
      handle: "@josh@etchit.io",
      actorUrl: "u",
      agentIdHex: "a".repeat(64),
      displayName: "Josh",
      bio: "hi",
      avatar: null,
      shareUri: "fetchit://share/v3/x",
      previousAgentIdHex: null,
      verifyFailure: null,
    };
    const card = renderActorCard(dto, { onOpenDm: () => {}, onViewProfile: (h) => { seen = h; } });
    (card.querySelector("[data-act=view-profile]") as HTMLElement).click();
    expect(seen).toBe("@josh@etchit.io");
  });
});
