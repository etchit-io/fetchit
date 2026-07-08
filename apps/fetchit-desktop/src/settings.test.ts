import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/app", () => ({
  getVersion: vi.fn(() => Promise.resolve("0.0.0-test")),
}));
vi.mock("./bookmarks", () => ({
  listBookmarks: vi.fn(() => Promise.resolve([])),
  addBookmark: vi.fn(() => Promise.resolve()),
  removeBookmark: vi.fn(() => Promise.resolve()),
}));
vi.mock("./theme/theme", () => ({
  loadTheme: vi.fn(() => "dark"),
  applyTheme: vi.fn(),
}));

// eslint-disable-next-line import/first
import { invoke } from "@tauri-apps/api/core";
// eslint-disable-next-line import/first
import { listBookmarks } from "./bookmarks";
// eslint-disable-next-line import/first
import { mountSettings, type SettingsHooks } from "./settings";
// eslint-disable-next-line import/first
import { MAX_BOOKMARKS_PER_QR } from "./bookmarkShare";
// eslint-disable-next-line import/first
import type { Bookmark } from "./bookmarks";

type InvokeMock = ReturnType<typeof vi.fn>;

function makeRouter(
  overrides: Record<string, (args?: Record<string, unknown>) => unknown> = {},
): (cmd: string, args?: Record<string, unknown>) => Promise<unknown> {
  const defaults: Record<string, (args?: Record<string, unknown>) => unknown> = {
    cache_stats: () => ({
      policy: { enabled: false, mode: "persist", maxBytes: 500 * 1024 * 1024 },
      sizeBytes: 0,
      fileCount: 0,
      path: "/tmp/cache",
    }),
    peer_count: () => 0,
    idle_policy: () => ({ timeoutMinutes: 30 }),
    lan_direct_enabled: () => false,
    peers_override: () => [],
    default_peers: () => [],
    relay_regions: () => [
      { tag: "nyc", label: "NYC (US East)", url: "http://67.207.94.66:8088" },
      { tag: "fra", label: "Frankfurt (EU)", url: "http://159.89.11.217:8088" },
    ],
    relay_url: () => "http://67.207.94.66:8088",
    set_relay_url: () => undefined,
    set_idle_policy: () => undefined,
    set_lan_direct_enabled: () => undefined,
    set_cache_policy: () => undefined,
    clear_cache: () => undefined,
    set_peers_override: (args) =>
      (args as { peers?: string[] } | undefined)?.peers ?? [],
    reset_peers_override: () => undefined,
    refresh_peers_from_upstream: () => ({ peers: [], updated: false }),
    display_name: () => "",
    set_display_name: () => undefined,
  };
  const table = { ...defaults, ...overrides };
  return (cmd: string, args?: Record<string, unknown>) => {
    const handler = table[cmd];
    if (!handler) return Promise.reject(new Error(`unmocked: ${cmd}`));
    try {
      const v = handler(args);
      if (v && typeof (v as Promise<unknown>).then === "function") {
        return v as Promise<unknown>;
      }
      return Promise.resolve(v);
    } catch (e) {
      return Promise.reject(e);
    }
  };
}

function defaultHooks(): SettingsHooks {
  return {
    onNavigate: vi.fn(),
    onBookmarksChanged: vi.fn(),
    onIdleChanged: vi.fn(),
    onShareBookmark: vi.fn(),
    onShareBookmarkList: vi.fn(),
  };
}

async function flush(): Promise<void> {
  // Several `void invoke(...).then(...)` chains require multiple
  // microtask drains before DOM-visible state settles.
  for (let i = 0; i < 8; i += 1) {
    await Promise.resolve();
  }
  await new Promise((r) => setTimeout(r, 0));
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve();
  }
}

let host: HTMLElement;

beforeEach(() => {
  host = document.createElement("section");
  document.body.appendChild(host);
  (invoke as unknown as InvokeMock).mockReset();
  (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
  vi.mocked(listBookmarks).mockReset();
  vi.mocked(listBookmarks).mockResolvedValue([]);
});

afterEach(() => {
  host.remove();
  delete document.body.dataset.view;
});

describe("LAN-direct toggle", () => {
  it("rolls back the checkbox when set_lan_direct_enabled rejects", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        set_lan_direct_enabled: () => {
          throw new Error("backend offline");
        },
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const box = host.querySelector<HTMLInputElement>("#lan-direct-enabled");
    expect(box).toBeTruthy();
    expect(box!.checked).toBe(false);
    box!.checked = true;
    box!.dispatchEvent(new Event("change"));
    await flush();
    expect(box!.checked).toBe(false);
  });

  it("keeps the new checked state when set_lan_direct_enabled resolves", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const box = host.querySelector<HTMLInputElement>("#lan-direct-enabled");
    box!.checked = true;
    box!.dispatchEvent(new Event("change"));
    await flush();
    expect(box!.checked).toBe(true);
  });
});

describe("relay region picker", () => {
  function selectEl(): HTMLSelectElement {
    return host.querySelector<HTMLSelectElement>("#relay-region")!;
  }
  function descEl(): HTMLElement {
    return host.querySelector<HTMLElement>("#relay-region-desc")!;
  }
  function customInput(): HTMLInputElement {
    return host.querySelector<HTMLInputElement>("#relay-custom-url")!;
  }
  function customSaveBtn(): HTMLButtonElement {
    return host.querySelector<HTMLButtonElement>("#relay-custom-save")!;
  }
  function customErr(): HTMLElement {
    return host.querySelector<HTMLElement>("#relay-custom-error")!;
  }

  it("renders KNOWN_RELAYS as options plus a Custom… entry, and picks the current URL", async () => {
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const opts = Array.from(selectEl().options).map((o) => o.value);
    expect(opts).toEqual(["nyc", "fra", "__custom__"]);
    expect(selectEl().value).toBe("nyc");
    expect(descEl().textContent).toContain("67.207.94.66:8088");
  });

  it("explains that moving relays republishes reachability and updates contacts", () => {
    mountSettings(host, defaultHooks());
    const network = host.querySelector<HTMLElement>("#group-network");
    expect(network?.textContent ?? "").toContain(
      "Moving relays republishes your reachability record; your contacts update automatically.",
    );
  });

  it("keeps every power control inside the collapsed Advanced section", () => {
    // Grandma bar: the primary settings surface carries only simple,
    // safe items. Relay/network config, bootstrap peers, the byte
    // cache, and advertised relays all live under Advanced; identity
    // backup deliberately stays first-class (recovery is critical
    // path).
    mountSettings(host, defaultHooks());
    const advanced = host.querySelector<HTMLElement>("#group-advanced")!;
    for (const id of [
      "relay-region",
      "relay-custom-url",
      "idle-timeout",
      "lan-direct-enabled",
      "advertised-relays-details",
      "peers-editor",
      "cache-enabled",
      "clear-cache",
    ]) {
      const el = host.querySelector(`#${id}`);
      expect(el, `#${id} must exist`).toBeTruthy();
      expect(advanced.contains(el), `#${id} must be inside Advanced`).toBe(true);
    }
    for (const id of ["group-backup", "group-bookmarks"]) {
      const el = host.querySelector(`#${id}`);
      expect(el, `#${id} must exist`).toBeTruthy();
      expect(advanced.contains(el), `#${id} must stay primary`).toBe(false);
    }
    const details = advanced.querySelector<HTMLDetailsElement>(
      ":scope > details.setting-collapsible",
    );
    expect(details, "Advanced must be collapsible").toBeTruthy();
    expect(details!.open, "Advanced must start collapsed").toBe(false);
  });

  it("invokes set_relay_url with the canonical URL when a region is picked", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();

    selectEl().value = "fra";
    selectEl().dispatchEvent(new Event("change"));
    await flush();

    const calls = (invoke as unknown as InvokeMock).mock.calls.filter(
      ([cmd]) => cmd === "set_relay_url",
    );
    expect(calls).toHaveLength(1);
    expect(calls[0][1]).toEqual({ url: "http://159.89.11.217:8088" });
    expect(descEl().textContent).toContain("159.89.11.217:8088");
  });

  it("treats a URL not in KNOWN_RELAYS as Custom and prefills the input", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        relay_url: () => "http://my-vps.example:8443",
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    expect(selectEl().value).toBe("__custom__");
    expect(customInput().value).toBe("http://my-vps.example:8443");
    expect(descEl().textContent).toContain("my-vps.example:8443");
  });

  it("validates the custom URL field and shows the backend error on rejection", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        set_relay_url: () => {
          throw new Error("invalid relay url: bad scheme");
        },
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();

    customInput().value = "not a url";
    customSaveBtn().click();
    await flush();
    expect(customErr().hidden).toBe(false);
    expect(customErr().textContent).toContain("bad scheme");
    // Dropdown should not have flipped to Custom — original NYC stays.
    expect(selectEl().value).toBe("nyc");
  });

  it("surfaces backend rejection of a path-bearing custom URL", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        set_relay_url: () => {
          throw new Error(
            "relay url must be a base URL with no path (got \"/v1/profile\")",
          );
        },
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();

    customInput().value = "http://relay.example:8088/v1/profile";
    customSaveBtn().click();
    await flush();
    expect(customErr().hidden).toBe(false);
    expect(customErr().textContent).toContain("no path");
  });

  it("never invokes set_relay_url with an empty trimmed URL", async () => {
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    customInput().value = "   ";
    customSaveBtn().click();
    await flush();
    const calls = (invoke as unknown as InvokeMock).mock.calls.filter(
      ([cmd]) => cmd === "set_relay_url",
    );
    expect(calls).toHaveLength(0);
    expect(customErr().textContent).toContain("Enter a URL");
  });
});

describe("idle-timeout select", () => {
  it("invokes set_idle_policy with the parsed minutes and fires onIdleChanged", async () => {
    const hooks = defaultHooks();
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, hooks);
    await api.open();
    await flush();
    const sel = host.querySelector<HTMLSelectElement>("#idle-timeout");
    expect(sel).toBeTruthy();
    sel!.value = "5";
    sel!.dispatchEvent(new Event("change"));
    await flush();
    const calls = (invoke as unknown as InvokeMock).mock.calls.filter(
      (c) => c[0] === "set_idle_policy",
    );
    expect(calls.length).toBe(1);
    expect(calls[0][1]).toEqual({ policy: { timeoutMinutes: 5 } });
    expect(hooks.onIdleChanged).toHaveBeenCalledWith(5);
  });
});

describe("peer editor", () => {
  it("save with only whitespace shows the empty-list error and never invokes set_peers_override", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const editor = host.querySelector<HTMLTextAreaElement>("#peers-editor");
    const saveBtn = host.querySelector<HTMLButtonElement>("#peers-save");
    const errorEl = host.querySelector<HTMLElement>("#peers-error");
    editor!.value = "   \n  \n\t\n";
    saveBtn!.dispatchEvent(new Event("click", { bubbles: true }));
    await flush();
    expect(errorEl!.hidden).toBe(false);
    expect(errorEl!.textContent).toMatch(/at least one peer is required/i);
    const savedCalls = (invoke as unknown as InvokeMock).mock.calls.filter(
      (c) => c[0] === "set_peers_override",
    );
    expect(savedCalls.length).toBe(0);
  });

  it("save trims and drops blank lines, then repopulates with the canonical list", async () => {
    let received: string[] = [];
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        set_peers_override: (args) => {
          received = (args as { peers: string[] }).peers;
          return ["clean://a", "clean://b"];
        },
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const editor = host.querySelector<HTMLTextAreaElement>("#peers-editor");
    const saveBtn = host.querySelector<HTMLButtonElement>("#peers-save");
    editor!.value = "  alpha\n\n   \n  beta  \n";
    saveBtn!.dispatchEvent(new Event("click", { bubbles: true }));
    await flush();
    expect(received).toEqual(["alpha", "beta"]);
    expect(editor!.value).toBe("clean://a\nclean://b");
  });

  it("renders the backend's string error and re-enables Save", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        set_peers_override: () => Promise.reject("bad addr"),
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const editor = host.querySelector<HTMLTextAreaElement>("#peers-editor");
    const saveBtn = host.querySelector<HTMLButtonElement>("#peers-save");
    const errorEl = host.querySelector<HTMLElement>("#peers-error");
    editor!.value = "some-peer";
    saveBtn!.dispatchEvent(new Event("click", { bubbles: true }));
    await flush();
    expect(errorEl!.textContent).toBe("bad addr");
    expect(errorEl!.hidden).toBe(false);
    expect(saveBtn!.disabled).toBe(false);
  });

  it("refresh-from-upstream shows pluralised status", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        refresh_peers_from_upstream: () => ({
          peers: ["one", "two", "three"],
          updated: true,
        }),
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const refreshBtn = host.querySelector<HTMLButtonElement>("#peers-refresh");
    const errorEl = host.querySelector<HTMLElement>("#peers-error");
    refreshBtn!.dispatchEvent(new Event("click", { bubbles: true }));
    await flush();
    expect(errorEl!.hidden).toBe(false);
    expect(errorEl!.textContent).toBe("Updated · 3 peers");
  });

  it("refresh-from-upstream uses singular 'peer' for a one-entry list", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({
        refresh_peers_from_upstream: () => ({
          peers: ["only-one"],
          updated: false,
        }),
      }),
    );
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const refreshBtn = host.querySelector<HTMLButtonElement>("#peers-refresh");
    const errorEl = host.querySelector<HTMLElement>("#peers-error");
    refreshBtn!.dispatchEvent(new Event("click", { bubbles: true }));
    await flush();
    expect(errorEl!.textContent).toBe("Already current · 1 peer");
  });
});

describe("bookmark share buttons", () => {
  function mkBookmarks(n: number): Bookmark[] {
    const bms: Bookmark[] = [];
    for (let i = 0; i < n; i += 1) {
      bms.push({
        address: i.toString(16).padStart(64, "0"),
        label: `bm-${i}`,
        createdAt: i,
      });
    }
    return bms;
  }

  it("caps the Share-all label and slices the payload when over the QR limit", async () => {
    const list = mkBookmarks(MAX_BOOKMARKS_PER_QR + 5);
    vi.mocked(listBookmarks).mockResolvedValue(list);
    const hooks = defaultHooks();
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, hooks);
    await api.open();
    await flush();
    const shareAll = host.querySelector<HTMLButtonElement>("#bookmarks-share-all");
    expect(shareAll).toBeTruthy();
    expect(shareAll!.textContent).toBe(
      `Share first ${MAX_BOOKMARKS_PER_QR} (of ${list.length})`,
    );
    shareAll!.dispatchEvent(new Event("click", { bubbles: true }));
    await flush();
    expect(hooks.onShareBookmarkList).toHaveBeenCalledTimes(1);
    const arg = (hooks.onShareBookmarkList as unknown as ReturnType<typeof vi.fn>)
      .mock.calls[0][0] as Bookmark[];
    expect(arg.length).toBe(MAX_BOOKMARKS_PER_QR);
  });

  it("Share-selected button label and disabled state track the row selection", async () => {
    const list: Bookmark[] = [
      { address: "a".repeat(64), label: "alpha", createdAt: 3 },
      { address: "b".repeat(64), label: "beta", createdAt: 2 },
      { address: "c".repeat(64), label: "gamma", createdAt: 1 },
    ];
    vi.mocked(listBookmarks).mockResolvedValue(list);
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const shareSelected = host.querySelector<HTMLButtonElement>(
      "#bookmarks-share-selected",
    );
    expect(shareSelected!.disabled).toBe(true);
    expect(shareSelected!.textContent).toBe("Share 0 selected");
    const checkboxes = host.querySelectorAll<HTMLInputElement>(
      ".bookmark-row .bookmark-select",
    );
    expect(checkboxes.length).toBe(3);
    checkboxes[0].checked = true;
    checkboxes[0].dispatchEvent(new Event("change", { bubbles: true }));
    checkboxes[2].checked = true;
    checkboxes[2].dispatchEvent(new Event("change", { bubbles: true }));
    expect(shareSelected!.disabled).toBe(false);
    expect(shareSelected!.textContent).toBe("Share 2 selected");
    checkboxes[0].checked = false;
    checkboxes[0].dispatchEvent(new Event("change", { bubbles: true }));
    checkboxes[2].checked = false;
    checkboxes[2].dispatchEvent(new Event("change", { bubbles: true }));
    expect(shareSelected!.disabled).toBe(true);
    expect(shareSelected!.textContent).toBe("Share 0 selected");
  });
});

describe("cache max-MB input", () => {
  it("clamps zero / negative input to 1 MB when sending set_cache_policy", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(makeRouter());
    const api = mountSettings(host, defaultHooks());
    await api.open();
    await flush();
    const maxMb = host.querySelector<HTMLInputElement>("#cache-max-mb");
    maxMb!.value = "0";
    maxMb!.dispatchEvent(new Event("change", { bubbles: true }));
    await flush();
    const setCalls = (invoke as unknown as InvokeMock).mock.calls.filter(
      (c) => c[0] === "set_cache_policy",
    );
    expect(setCalls.length).toBeGreaterThan(0);
    const lastZero = setCalls[setCalls.length - 1][1] as {
      policy: { maxBytes: number };
    };
    expect(lastZero.policy.maxBytes).toBe(1024 * 1024);

    maxMb!.value = "-15";
    maxMb!.dispatchEvent(new Event("change", { bubbles: true }));
    await flush();
    const after = (invoke as unknown as InvokeMock).mock.calls.filter(
      (c) => c[0] === "set_cache_policy",
    );
    const last = after[after.length - 1][1] as {
      policy: { maxBytes: number };
    };
    expect(last.policy.maxBytes).toBe(1024 * 1024);
  });
});

describe("settings view my profile", () => {
  it("exposes a View my profile control", () => {
    mountSettings(host, defaultHooks());
    expect(host.querySelector("[data-act=view-my-profile]")).not.toBeNull();
  });

  it("calls onViewMyProfile when the control is clicked", () => {
    const onViewMyProfile = vi.fn();
    mountSettings(host, { ...defaultHooks(), onViewMyProfile });
    const btn = host.querySelector<HTMLButtonElement>("[data-act=view-my-profile]");
    expect(btn).not.toBeNull();
    btn!.click();
    expect(onViewMyProfile).toHaveBeenCalledTimes(1);
  });
});

describe("display name", () => {
  it("lives at the top level, not inside Advanced", () => {
    mountSettings(host, defaultHooks());
    const section = host.querySelector("#group-name");
    expect(section).not.toBeNull();
    expect(section?.closest("#group-advanced")).toBeNull();
    expect(section?.closest("details")).toBeNull();
  });

  it("populates from the backend and saves the trimmed name", async () => {
    (invoke as unknown as InvokeMock).mockImplementation(
      makeRouter({ display_name: () => "Alice" }),
    );
    mountSettings(host, defaultHooks());
    await flush();
    const input = host.querySelector<HTMLInputElement>("#display-name-input");
    expect(input?.value).toBe("Alice");

    input!.value = "  Alice B  ";
    host.querySelector<HTMLButtonElement>("[data-act=save-name]")!.click();
    await flush();
    expect(invoke).toHaveBeenCalledWith("set_display_name", { name: "Alice B" });
    const status = host.querySelector<HTMLParagraphElement>("#display-name-status");
    expect(status?.hidden).toBe(false);
    expect(status?.textContent).toContain("Saved");
  });

  it("refuses an empty name without calling the backend", async () => {
    mountSettings(host, defaultHooks());
    await flush();
    const input = host.querySelector<HTMLInputElement>("#display-name-input")!;
    input.value = "   ";
    (invoke as unknown as InvokeMock).mockClear();
    host.querySelector<HTMLButtonElement>("[data-act=save-name]")!.click();
    await flush();
    expect(invoke).not.toHaveBeenCalledWith("set_display_name", expect.anything());
    const status = host.querySelector<HTMLParagraphElement>("#display-name-status");
    expect(status?.textContent).toContain("empty");
  });
});
