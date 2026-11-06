import { createLogger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type {
  SecretRef,
  SecretVersionRef,
} from "@p0security/connector-secret-manager-client";
import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { t } from "../../../router.ts";
import { router } from "../handler.ts";

vi.mock("../../../sleep.ts", () => ({ sleep: async () => undefined }));

const ADMIN_REF = "admin-token";
const ADMIN_KEY = "admin-token-value";
const ADMIN_ID = "tok-admin";
const MEMBER = 1908146;
const GRANT_REF = "projects/1/secrets/p0_access-token_gitguardian_942194_abc";
const PREFIX = `P0 ${createHash("sha256").update(GRANT_REF).digest("hex").slice(0, 16)} `;

// V1's real response bodies.
const CAP_FULL =
  "The limit of 5 active personal access tokens is reached for this member.";
const ALREADY_REVOKED = "This token has already been revoked";

/** In-memory secrets: ref → latest value. */
const store = new Map<string, string>();
const secretNames = new Set<string>();
const writes = { fail: false };

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
        createSecretVersion: async ({
          ref,
          value,
        }: {
          ref: string;
          value: Buffer;
        }) => {
          if (writes.fail) throw new Error("write failed");
          store.set(ref, value.toString("utf8"));
        },
        deleteSecret: async ({ ref }: { ref: string }) => {
          store.delete(ref);
        },
        createSecret: async ({ name }: { name: string }) => {
          secretNames.add(name);
          return { ref: `projects/1/secrets/${name}`, name };
        },
        getSecret: async ({ ref }: { ref: string }) => {
          const name = ref.split("/").pop() ?? ref;
          if (!secretNames.has(name))
            throw new actual.SecretNotFoundError(ref as SecretRef);
          return { ref, name };
        },
      }),
    };
  }
);

type FakeToken = {
  id: string;
  name: string;
  type: "personal_access_token";
  scopes: string[];
  member_id: number;
  workspace_id: number;
  expire_at: string | null;
  status: "active" | "revoked";
  key: string;
};

/** A fake GitGuardian for one member: the cap is 5 active tokens, the admin
 * token counts, and a second DELETE answers 403, as V1 found. */
const gg = {
  tokens: [] as FakeToken[],
  nextId: 1,
  mintBodies: [] as Record<string, unknown>[],
  deleted: [] as string[],
  conflicts: 0,
  deleteFailures: new Map<string, { status: number; detail: string }>(),
};

const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), { status });

const fakeFetch = async (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string }
) => {
  const { pathname } = new URL(url);
  const caller = gg.tokens.find(
    (token) =>
      init.headers.Authorization === `Token ${token.key}` &&
      token.status === "active"
  );
  if (!caller) return json(401, { detail: "Invalid API key." });
  const active = () => gg.tokens.filter((token) => token.status === "active");
  const record = ({ key: _key, ...token }: FakeToken) => token;

  if (init.method === "GET" && pathname === "/v1/api_tokens/self")
    return json(200, record(caller));
  if (init.method === "GET" && pathname === "/v1/api_tokens")
    return json(200, active().map(record));
  if (init.method === "POST" && pathname === "/v1/api_tokens") {
    const body = JSON.parse(init.body ?? "{}");
    gg.mintBodies.push(body);
    if (gg.conflicts > 0) {
      gg.conflicts -= 1;
      return json(409, { detail: "Another token is already being created" });
    }
    if (active().length >= 5) return json(400, { detail: CAP_FULL });
    const scopes = [...body.scopes];
    if (
      scopes.includes("incidents:write") &&
      !scopes.includes("incidents:read")
    )
      scopes.push("incidents:read");
    const token: FakeToken = {
      id: `tok-${gg.nextId++}`,
      name: body.name,
      type: body.type,
      scopes,
      member_id: MEMBER,
      workspace_id: 942194,
      expire_at: new Date(
        Date.now() + body.lifetime * 86_400_000
      ).toISOString(),
      status: "active",
      key: `key-${gg.nextId}`,
    };
    gg.tokens.push(token);
    return json(201, token);
  }
  const match = pathname.match(/^\/v1\/api_tokens\/(.+)$/);
  if (init.method === "DELETE" && match) {
    const id = decodeURIComponent(match[1]);
    const failure = gg.deleteFailures.get(id);
    if (failure) return json(failure.status, { detail: failure.detail });
    const token = gg.tokens.find((each) => each.id === id);
    if (!token) return json(404, { detail: "Not found." });
    if (token.status === "revoked")
      return json(403, { detail: ALREADY_REVOKED });
    token.status = "revoked";
    gg.deleted.push(id);
    return json(204);
  }
  return json(400, { detail: `unexpected ${init.method} ${pathname}` });
};
const mockedFetch = vi.fn(fakeFetch);
vi.stubGlobal("fetch", mockedFetch);

const addToken = (overrides: Partial<FakeToken>) => {
  const token: FakeToken = {
    id: `tok-${gg.nextId++}`,
    name: `${PREFIX}1`,
    type: "personal_access_token",
    scopes: ["scan"],
    member_id: MEMBER,
    workspace_id: 942194,
    expire_at: null,
    status: "active",
    key: `key-${gg.nextId}`,
    ...overrides,
  };
  gg.tokens.push(token);
  return token;
};

const context = () => ({
  requestId: "r-1",
  region: "us" as const,
  workspaceId: "942194",
  secrets: {
    manager: "gcp" as const,
    adminTokenSecretId: ADMIN_REF,
    projectId: "p",
  },
});

const caller = () => router(t).createCaller({ logger: createLogger() });

const setPolicies = (scopes: string[], grantEndsAt: string | null = null) =>
  caller().setPoliciesForUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    policies: [{ scopes, grantEndsAt }],
    context: context(),
  });

const deleteUser = () =>
  caller().deleteUser({
    userId: GRANT_REF,
    userBody: "p0_grant",
    context: context(),
  });

const activeIds = () =>
  gg.tokens.filter((token) => token.status === "active").map(({ id }) => id);

beforeEach(() => {
  store.clear();
  secretNames.clear();
  writes.fail = false;
  store.set(ADMIN_REF, ADMIN_KEY);
  gg.tokens = [];
  gg.nextId = 1;
  gg.mintBodies = [];
  gg.deleted = [];
  gg.conflicts = 0;
  gg.deleteFailures.clear();
  addToken({
    id: ADMIN_ID,
    name: "P0 connector admin",
    key: ADMIN_KEY,
    scopes: [
      "scan",
      "incidents:read",
      "incidents:write",
      "sources:read",
      "members:read",
      "api_tokens:read",
      "api_tokens:write",
    ],
  });
  mockedFetch.mockClear();
});

describe("grant", () => {
  it("mints a token named for the grant and stores only its key", async () => {
    await setPolicies(["sources:read", "incidents:read"]);

    expect(gg.mintBodies).toEqual([
      {
        name: expect.stringMatching(new RegExp(`^${PREFIX}\\d+$`)),
        type: "personal_access_token",
        scopes: ["incidents:read", "sources:read"],
        lifetime: 365,
      },
    ]);
    const minted = gg.tokens.at(-1)!;
    expect(store.get(GRANT_REF)).toBe(minted.key);
  });

  it("sets the lifetime to the longest grant's end, rounded up", async () => {
    const endsAt = new Date(Date.now() + 2.5 * 86_400_000).toISOString();

    await setPolicies(["scan"], endsAt);

    expect(gg.mintBodies[0]).toMatchObject({ lifetime: 3 });
  });

  it("gives a grant that ends within a day a lifetime of 1", async () => {
    const endsAt = new Date(Date.now() + 60_000).toISOString();

    await setPolicies(["scan"], endsAt);

    expect(gg.mintBodies[0]).toMatchObject({ lifetime: 1 });
  });

  it("takes the end from the policy, not the request context", async () => {
    const endsAt = new Date(Date.now() + 30 * 86_400_000).toISOString();

    await caller().setPoliciesForUser({
      userId: GRANT_REF,
      userBody: "p0_grant",
      policies: [{ scopes: ["scan"], grantEndsAt: null }],
      context: { ...context(), grantEndsAt: endsAt } as any,
    });

    expect(gg.mintBodies[0]).toMatchObject({ lifetime: 365 });
  });
});

describe("change", () => {
  it("mints a new token, stores it, then revokes the old one", async () => {
    const old = addToken({ name: `${PREFIX}100` });

    await setPolicies(["incidents:write"]);

    const minted = gg.tokens.at(-1)!;
    expect(store.get(GRANT_REF)).toBe(minted.key);
    expect(gg.deleted).toEqual([old.id]);
    expect(activeIds()).toEqual([ADMIN_ID, minted.id]);
  });

  it("succeeds when the old token can't be revoked", async () => {
    const old = addToken({ name: `${PREFIX}100` });
    gg.deleteFailures.set(old.id, { status: 400, detail: "bad request" });

    await setPolicies(["scan"]);

    expect(store.get(GRANT_REF)).toBe(gg.tokens.at(-1)!.key);
    expect(activeIds()).toContain(old.id);
  });

  it("never revokes the admin token or a token without the grant's prefix", async () => {
    const other = addToken({ name: "P0 0123456789abcdef 100" });
    const customers = addToken({ name: "CI scanner" });

    await setPolicies(["scan"]);

    expect(gg.deleted).toEqual([]);
    expect(activeIds()).toEqual(
      expect.arrayContaining([ADMIN_ID, other.id, customers.id])
    );
  });
});

describe("refusals", () => {
  it("refuses a scope outside the requestable ones without calling GitGuardian", async () => {
    await expect(setPolicies(["scan", "api_tokens:write"])).rejects.toThrow(
      "P0 can't grant api_tokens:write."
    );
    expect(mockedFetch).not.toHaveBeenCalled();
  });

  it("refuses a scope the admin token doesn't hold, naming it", async () => {
    gg.tokens[0].scopes = ["scan", "api_tokens:read", "api_tokens:write"];

    await expect(setPolicies(["members:read"])).rejects.toThrow(
      "The admin token for workspace 942194 doesn't hold members:read."
    );
    expect(gg.mintBodies).toEqual([]);
  });

  it("refuses with the cap message when the member has no free slot", async () => {
    for (const n of [1, 2, 3, 4]) addToken({ name: `someone else ${n}` });

    await expect(setPolicies(["scan"])).rejects.toThrow(
      "GitGuardian workspace 942194 has no free API token slots."
    );
    expect(store.has(GRANT_REF)).toBe(false);
  });
});

describe("retries", () => {
  it("retries a 409 and then mints", async () => {
    gg.conflicts = 1;

    await setPolicies(["scan"]);

    expect(gg.mintBodies).toHaveLength(2);
    expect(store.get(GRANT_REF)).toBe(gg.tokens.at(-1)!.key);
  });

  it("fails after four 409s", async () => {
    gg.conflicts = 4;

    await expect(setPolicies(["scan"])).rejects.toThrow(/409/);
    expect(gg.mintBodies).toHaveLength(4);
  });
});

describe("failed secret write", () => {
  it("revokes the token it just minted", async () => {
    writes.fail = true;

    await expect(setPolicies(["scan"])).rejects.toThrow("write failed");

    expect(activeIds()).toEqual([ADMIN_ID]);
  });
});

describe("revoke", () => {
  it("revokes the grant's token, then deletes the secret", async () => {
    const token = addToken({});
    store.set(GRANT_REF, token.key);

    await deleteUser();

    expect(gg.deleted).toEqual([token.id]);
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("revokes the token when no scopes remain", async () => {
    const token = addToken({});

    await setPolicies([]);

    expect(gg.deleted).toEqual([token.id]);
    expect(gg.mintBodies).toEqual([]);
  });

  it.each([
    [404, "Not found."],
    [403, ALREADY_REVOKED],
  ])("treats a %s token as already gone", async (status, detail) => {
    const token = addToken({});
    gg.deleteFailures.set(token.id, { status, detail });
    store.set(GRANT_REF, token.key);

    await deleteUser();

    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("treats any other 403 as a failure", async () => {
    const token = addToken({});
    gg.deleteFailures.set(token.id, {
      status: 403,
      detail: "Permission denied",
    });
    store.set(GRANT_REF, token.key);

    await expect(deleteUser()).rejects.toThrow(
      `P0 couldn't revoke GitGuardian token ${token.id} (403)`
    );
    expect(store.has(GRANT_REF)).toBe(true);
  });

  it("retries a 500, then fails and keeps the secret for the next try", async () => {
    const token = addToken({});
    gg.deleteFailures.set(token.id, { status: 500, detail: "oops" });
    store.set(GRANT_REF, token.key);

    await expect(deleteUser()).rejects.toThrow(
      `P0 couldn't revoke GitGuardian token ${token.id} (500)`
    );
    expect(
      mockedFetch.mock.calls.filter(([, init]) => init.method === "DELETE")
    ).toHaveLength(4);
    expect(store.get(GRANT_REF)).toBe(token.key);
  });
});

describe("list", () => {
  it("lists the requestable scopes without calling GitGuardian", async () => {
    const scopes = await caller().list({
      query: {
        type: "scope",
        context: {
          region: "us",
          workspaceId: "942194",
          secrets: context().secrets,
        },
      },
    });

    expect(scopes.map(({ key }) => key)).toEqual([
      "scan",
      "incidents:read",
      "incidents:write",
      "sources:read",
      "members:read",
    ]);
    expect(mockedFetch).not.toHaveBeenCalled();
  });
});
