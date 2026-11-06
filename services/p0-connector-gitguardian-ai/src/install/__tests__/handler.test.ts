import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type { SecretVersionRef } from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { t } from "../../router.ts";
import { router } from "../handler.ts";

const ADMIN_REF = "admin-token";
const TOKEN = "admin-token-value";
const WORKSPACE = "942194";

/** In-memory secrets: ref → value. */
const store = new Map<string, string>();

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SecretManagerClientModule>();
    return {
      ...actual,
      createSecretManagerClient: async () => ({
        getSecretValue: async ({ ref }: { ref: string }) => {
          const value = store.get(ref);
          if (value === undefined)
            throw new actual.SecretVersionNotFoundError(
              ref as SecretVersionRef
            );
          return { value };
        },
      }),
    };
  }
);

/** A fake GitGuardian `/v1/api_tokens/self`: the US host knows `TOKEN`, and
 * answers 401 for any other key or host, as GitGuardian does. */
const tokenRecord = { current: {} as Record<string, unknown> };
const mockedFetch = vi.fn(
  async (url: string, init: { headers: Record<string, string> }) => {
    const known =
      url === "https://api.gitguardian.com/v1/api_tokens/self" &&
      init.headers.Authorization === `Token ${TOKEN}`;
    return known
      ? {
          ok: true,
          status: 200,
          statusText: "",
          json: async () => tokenRecord.current,
        }
      : {
          ok: false,
          status: 401,
          statusText: "",
          json: async () => ({ detail: "Invalid API key." }),
        };
  }
);
vi.stubGlobal("fetch", mockedFetch);

const adminToken = (overrides: Record<string, unknown> = {}) => ({
  id: "tok-admin",
  name: "P0 connector admin",
  type: "personal_access_token",
  scopes: ["scan", "incidents:write", "api_tokens:write"],
  member_id: 1908146,
  workspace_id: 942194,
  expire_at: null,
  status: "active",
  ...overrides,
});

const input = {
  region: "us" as const,
  workspaceId: WORKSPACE,
  secrets: {
    manager: "gcp" as const,
    adminTokenSecretId: ADMIN_REF,
    projectId: "p",
  },
};

const validate = (body: unknown = input) =>
  router(t)
    .createCaller({ logger: createLogger() })
    .get(body as typeof input);

beforeEach(() => {
  store.clear();
  store.set(ADMIN_REF, TOKEN);
  tokenRecord.current = adminToken();
  mockedFetch.mockClear();
});

describe("install validation", () => {
  it("returns the admin token it checked", async () => {
    await expect(validate()).resolves.toEqual({
      tokenId: "tok-admin",
      workspaceId: WORKSPACE,
      memberId: 1908146,
      type: "personal_access_token",
      scopes: ["scan", "incidents:write", "api_tokens:write"],
      expireAt: null,
    });
  });

  it("trims a trailing newline from the stored token", async () => {
    store.set(ADMIN_REF, `${TOKEN}\n`);

    await expect(validate()).resolves.toMatchObject({ tokenId: "tok-admin" });
  });

  it("refuses an empty secret", async () => {
    store.set(ADMIN_REF, "  \n");

    await expect(validate()).rejects.toThrow(/admin token secret is empty/);
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("refuses a token GitGuardian rejects in the region", async () => {
    await expect(validate({ ...input, region: "eu" })).rejects.toThrow(
      /rejected the admin token in the eu region/
    );
  });

  it("refuses a token that is not active", async () => {
    tokenRecord.current = adminToken({ status: "expired" });

    await expect(validate()).rejects.toThrow(/admin token is expired/);
  });

  it("refuses a token from another workspace, naming both", async () => {
    tokenRecord.current = adminToken({ workspace_id: 111 });

    await expect(validate()).rejects.toThrow(
      "The admin token belongs to workspace 111, but this install is for workspace 942194."
    );
  });

  it("refuses a token without api_tokens:write", async () => {
    tokenRecord.current = adminToken({ scopes: ["scan", "incidents:read"] });

    await expect(validate()).rejects.toThrow(/without api_tokens:write/);
  });

  it("does not require the requestable scopes", async () => {
    tokenRecord.current = adminToken({ scopes: ["api_tokens:write"] });

    await expect(validate()).resolves.toMatchObject({
      scopes: ["api_tokens:write"],
    });
  });

  it.each([
    ["an unknown field", { ...input, owner: "someone" }],
    ["a region outside us and eu", { ...input, region: "ap1" }],
    ["a workspace ID that is not numeric", { ...input, workspaceId: "abc" }],
  ])("rejects input with %s", async (_, body) => {
    await expect(validate(body)).rejects.toThrow();
    expect(mockedFetch).not.toHaveBeenCalled();
  });
});
