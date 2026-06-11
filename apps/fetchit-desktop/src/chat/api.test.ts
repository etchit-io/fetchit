import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string, args?: unknown) => invokeMock(cmd, args),
}));

import { importPairUri, pairShareUri } from "./api";

beforeEach(() => {
  invokeMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("pairShareUri", () => {
  it("invokes chat_pair_share_uri and returns the pointer URI", async () => {
    invokeMock.mockResolvedValueOnce("x0x://pair/" + "ab".repeat(32) + "?r=https%3A%2F%2Fr.example");
    const uri = await pairShareUri();
    expect(invokeMock).toHaveBeenCalledWith("chat_pair_share_uri", undefined);
    expect(uri).toContain("x0x://pair/");
  });

  it("propagates a bare-string publish failure verbatim", async () => {
    invokeMock.mockRejectedValueOnce("relay unreachable");
    await expect(pairShareUri()).rejects.toBe("relay unreachable");
  });
});

describe("importPairUri", () => {
  it("invokes chat_import_pair_uri with the uri arg", async () => {
    invokeMock.mockResolvedValueOnce(undefined);
    await importPairUri("x0x://pair/abc?r=https://r.example");
    expect(invokeMock).toHaveBeenCalledWith("chat_import_pair_uri", {
      uri: "x0x://pair/abc?r=https://r.example",
    });
  });

  it("propagates the import error to the caller", async () => {
    invokeMock.mockRejectedValueOnce(new Error("could not reach any of their relays"));
    await expect(importPairUri("x0x://pair/x?r=https://r.example")).rejects.toThrow(
      "could not reach any of their relays",
    );
  });
});
