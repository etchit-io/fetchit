import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { CONFIRM_COPY, mountCompose, resetConfirmForTests } from "./compose";

type InvokeMock = ReturnType<typeof vi.fn>;

const mock = invoke as InvokeMock;

function statusResolves(handle: string | null): void {
  mock.mockImplementation((cmd: string) => {
    if (cmd === "fediverse_actor_status") return Promise.resolve(handle);
    if (cmd === "fediverse_publish")
      return Promise.resolve({ delivered: [], failed: [] });
    return Promise.resolve(null);
  });
}

async function mountWith(handle: string | null): Promise<HTMLElement> {
  statusResolves(handle);
  const host = document.createElement("div");
  document.body.append(host);
  const api = mountCompose(host);
  await api.ready;
  return host;
}

function publishCalls(): unknown[][] {
  return mock.mock.calls.filter((c) => c[0] === "fediverse_publish");
}

beforeEach(() => {
  mock.mockReset();
  resetConfirmForTests();
  document.body.innerHTML = "";
});

describe("compose: mint onboarding", () => {
  it("shows the mint affordance when no handle is minted", async () => {
    const host = await mountWith(null);
    expect(host.querySelector(".fediverse-compose__mint-input")).not.toBeNull();
    expect(host.querySelector(".fediverse-compose__textarea")).toBeNull();
  });

  it("mint help carries the one-opt-in consent copy", async () => {
    const host = await mountWith(null);
    const help = host.querySelector(".fediverse-compose__mint-help")!;
    expect(help.textContent).toContain("publicly findable and contactable");
  });

  it("rejects an invalid handle client-side without invoking mint", async () => {
    const host = await mountWith(null);
    const input = host.querySelector<HTMLInputElement>(".fediverse-compose__mint-input")!;
    input.value = "bad handle!";
    host.querySelector<HTMLButtonElement>(".fediverse-compose__mint-btn")!.click();
    expect(host.querySelector(".fediverse-compose__mint-error")!.textContent).toMatch(/1-64/);
    expect(mock.mock.calls.filter((c) => c[0] === "fediverse_mint")).toHaveLength(0);
  });

  it("mints a valid handle and swaps to the composer", async () => {
    const host = await mountWith(null);
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_mint"
        ? Promise.resolve({
            actorUrl: "https://etchit.io/actors/josh",
            registered: true,
            registrationError: null,
          })
        : Promise.resolve(null),
    );
    const input = host.querySelector<HTMLInputElement>(".fediverse-compose__mint-input")!;
    input.value = "josh";
    host.querySelector<HTMLButtonElement>(".fediverse-compose__mint-btn")!.click();
    await vi.waitFor(() => {
      expect(host.querySelector(".fediverse-compose__textarea")).not.toBeNull();
    });
    const mintCall = mock.mock.calls.find((c) => c[0] === "fediverse_mint")!;
    expect(mintCall[1]).toEqual({ handle: "josh" });
    expect(host.querySelector(".fediverse-compose__mint-pending")).toBeNull();
  });

  it("renders registration-pending honestly when the directory is unreachable", async () => {
    const host = await mountWith(null);
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_mint"
        ? Promise.resolve({
            actorUrl: "https://etchit.io/actors/josh",
            registered: false,
            registrationError: "transport: connection refused",
          })
        : Promise.resolve(null),
    );
    const input = host.querySelector<HTMLInputElement>(".fediverse-compose__mint-input")!;
    input.value = "josh";
    host.querySelector<HTMLButtonElement>(".fediverse-compose__mint-btn")!.click();
    await vi.waitFor(() => {
      expect(host.querySelector(".fediverse-compose__textarea")).not.toBeNull();
    });
    const pending = host.querySelector(".fediverse-compose__mint-pending")!;
    expect(pending.textContent).toContain("Directory registration pending");
    expect(pending.textContent).toContain("connection refused");
  });

  it("runs the v2 upgrade pass when a handle already exists", async () => {
    await mountWith("josh");
    await vi.waitFor(() => {
      expect(mock.mock.calls.some((c) => c[0] === "fediverse_ensure_v2")).toBe(true);
    });
  });
});

describe("compose: publish confirmation", () => {
  async function composerWithText(text: string): Promise<HTMLElement> {
    const host = await mountWith("josh");
    host.querySelector<HTMLTextAreaElement>(".fediverse-compose__textarea")!.value = text;
    return host;
  }

  it("opens the modal with the spec copy and does NOT publish until accepted", async () => {
    const host = await composerWithText("hello world");
    host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!.click();
    expect(host.querySelector(".fediverse-confirm__copy")!.textContent).toBe(CONFIRM_COPY);
    expect(publishCalls()).toHaveLength(0);
    host.querySelector<HTMLButtonElement>(".fediverse-confirm__accept")!.click();
    await vi.waitFor(() => expect(publishCalls()).toHaveLength(1));
  });

  it("cancel closes the modal without publishing", async () => {
    const host = await composerWithText("hello");
    host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!.click();
    host.querySelector<HTMLButtonElement>(".fediverse-confirm__cancel")!.click();
    expect(host.querySelector(".fediverse-confirm")).toBeNull();
    expect(publishCalls()).toHaveLength(0);
  });

  it("disables the post button while the modal is open, re-enables on cancel", async () => {
    const host = await composerWithText("hello");
    const postBtn = host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!;
    postBtn.click();
    expect(postBtn.disabled).toBe(true);
    postBtn.click();
    expect(host.querySelectorAll(".fediverse-confirm")).toHaveLength(1);
    host.querySelector<HTMLButtonElement>(".fediverse-confirm__cancel")!.click();
    expect(postBtn.disabled).toBe(false);
  });

  it("don't-ask-again skips the modal for the rest of the session", async () => {
    const host = await composerWithText("first");
    host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!.click();
    host.querySelector<HTMLInputElement>(".fediverse-confirm__tick input")!.checked = true;
    host.querySelector<HTMLButtonElement>(".fediverse-confirm__accept")!.click();
    await vi.waitFor(() => expect(publishCalls()).toHaveLength(1));

    host.querySelector<HTMLTextAreaElement>(".fediverse-compose__textarea")!.value = "second";
    host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!.click();
    expect(host.querySelector(".fediverse-confirm")).toBeNull();
    await vi.waitFor(() => expect(publishCalls()).toHaveLength(2));
  });

  it("threads the reply target through publish and clears it after", async () => {
    statusResolves("josh");
    const host = document.createElement("div");
    document.body.append(host);
    const api = mountCompose(host);
    await api.ready;

    api.setReplyTo("https://m.example/users/bob");
    const chip = host.querySelector<HTMLElement>(".fediverse-compose__reply")!;
    expect(chip.hidden).toBe(false);
    expect(chip.textContent).toContain("https://m.example/users/bob");

    host.querySelector<HTMLTextAreaElement>(".fediverse-compose__textarea")!.value = "re";
    host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!.click();
    host.querySelector<HTMLButtonElement>(".fediverse-confirm__accept")!.click();
    await vi.waitFor(() => expect(publishCalls()).toHaveLength(1));
    expect(publishCalls()[0][1]).toEqual({
      bodyMd: "re",
      replyToActorUrl: "https://m.example/users/bob",
      replyToObjectUrl: null,
    });
    await vi.waitFor(() => expect(chip.hidden).toBe(true));
  });

  it("clears the textarea and reports counts on success", async () => {
    const host = await composerWithText("hi @ann@x.io");
    mock.mockImplementation((cmd: string) =>
      cmd === "fediverse_publish"
        ? Promise.resolve({ delivered: ["https://x.io/inbox"], failed: [] })
        : Promise.resolve("josh"),
    );
    host.querySelector<HTMLButtonElement>(".fediverse-compose__post")!.click();
    host.querySelector<HTMLButtonElement>(".fediverse-confirm__accept")!.click();
    await vi.waitFor(() => {
      expect(host.querySelector(".fediverse-compose__result")!.textContent).toBe(
        "delivered 1 · failed 0",
      );
    });
    expect(host.querySelector<HTMLTextAreaElement>(".fediverse-compose__textarea")!.value).toBe("");
  });
});
