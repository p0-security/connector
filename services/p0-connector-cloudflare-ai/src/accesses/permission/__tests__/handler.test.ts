import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type { SecretRef } from "@p0security/connector-secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACCOUNT_ID,
  AWS_SECRET,
  connectorError,
  logger,
  recordLogger,
  stubToken,
} from "../../../__tests__/fixtures.ts";
import {
  failed,
  ok,
  stubCloudflare,
} from "../../../cloudflare/__tests__/fake-cloudflare.ts";
import { CLOUDFLARE_API } from "../../../cloudflare/cloudflare-api.ts";
import { TOKEN_CAP_MESSAGE } from "../../../cloudflare/errors.ts";
import { connectorRouter } from "../../../router.ts";
import type * as SecretsModule from "../../../secrets.ts";
import type { Policy } from "../definition.ts";

// The install token's read is `secrets.ts`'s business. Here it answers with
// the token.
vi.mock("../../../secrets.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof SecretsModule>()),
  readToken: vi.fn(),
}));

/** What happened, in order, across Cloudflare and the secret manager. */
const events: string[] = [];

/** In-memory grant secrets: ref → latest value. */
const store = new Map<string, string>();
const secrets = new Set<string>();
const writes = { fail: false };

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SecretManagerClientModule>();
    return {
      ...actual,
      createSecretManagerClient: async () => ({
        createSecretVersion: async ({
          ref,
          value,
        }: {
          ref: string;
          value: Buffer;
        }) => {
          if (writes.fail) throw new Error("write failed");
          events.push("write secret");
          store.set(ref, value.toString("utf8"));
        },
        deleteSecret: async ({ ref }: { ref: string }) => {
          events.push("delete secret");
          store.delete(ref);
          secrets.delete(ref);
        },
        createSecret: async ({ name }: { name: string }) => {
          secrets.add(name);
          return { name, ref: `arn:secret:${name}` };
        },
        getSecret: async ({ ref }: { ref: string }) => {
          const name = ref.replace(/^arn:secret:/, "");
          if (!secrets.has(name)) {
            throw new actual.SecretNotFoundError(ref as SecretRef);
          }
          return { name, ref: `arn:secret:${name}` };
        },
      }),
    };
  }
);

const ACCOUNT = `/accounts/${ACCOUNT_ID}`;
const ACCOUNT_KEY = `com.cloudflare.api.account.${ACCOUNT_ID}`;
const GRANT_REF = "arn:secret:grant";
const TOKEN_NAME = `P0 ${GRANT_REF}`;
const EXPIRES_ON = "2026-11-05T12:00:00Z";

const context = { accountId: ACCOUNT_ID, requestId: "r-1", secret: AWS_SECRET };

const ACCOUNT_GROUPS: Policy = {
  expiresOn: EXPIRES_ON,
  resources: [{ groups: ["dns-read"], scope: "account" }],
};

const REVOKE: Policy = { resources: [] };

type FakeToken = { id: string; name: string };

/**
 * A Cloudflare account that keeps its tokens between calls, so a test can
 * run a call again after it fails. Minted tokens are `minted-1`,
 * `minted-2`, and so on, with value `value-<id>`.
 */
const fakeAccount = ({
  tokens = [],
  zones = [],
}: { tokens?: FakeToken[]; zones?: { id: string; name: string }[] } = {}) => {
  const state = {
    /** Token ids whose `DELETE` fails, until removed. */
    failDelete: new Set<string>(),
    /** The answer to the next mint, in place of a token. */
    mintFails: undefined as (() => Response) | undefined,
    /** Token ids whose `PUT` fails, until removed. */
    failUpdate: new Set<string>(),
    tokens: [...tokens],
  };
  let minted = 0;
  const ids = [
    ...tokens.map(({ id }) => id),
    ...[1, 2, 3, 4].map((n) => `minted-${n}`),
  ];
  const cloudflare = stubCloudflare({
    [`GET ${ACCOUNT}/tokens`]: () =>
      ok(
        state.tokens.map((token) => ({ ...token, status: "active" })),
        { page: 1, total_pages: 1 }
      ),
    [`POST ${ACCOUNT}/tokens`]: () => {
      const failure = state.mintFails;
      if (failure !== undefined) {
        state.mintFails = undefined;
        events.push("mint failed");
        return failure();
      }
      const id = `minted-${++minted}`;
      state.tokens.push({ id, name: TOKEN_NAME });
      events.push(`mint ${id}`);
      return ok({ id, value: `value-${id}` });
    },
    "GET /zones": () => ok(zones, { page: 1, total_pages: 1 }),
    ...Object.fromEntries(
      ids.flatMap((id) => [
        [
          `PUT ${ACCOUNT}/tokens/${id}`,
          () => {
            if (state.failUpdate.has(id)) {
              return failed(500, [{ code: 1, message: "down" }]);
            }
            events.push(`update ${id}`);
            return ok({ id });
          },
        ],
        [
          `DELETE ${ACCOUNT}/tokens/${id}`,
          () => {
            if (state.failDelete.has(id)) {
              return failed(500, [{ code: 1, message: "down" }]);
            }
            events.push(`delete ${id}`);
            state.tokens = state.tokens.filter((token) => token.id !== id);
            return ok({ id });
          },
        ],
      ])
    ),
  });
  return { cloudflare, state };
};

const permission = () =>
  connectorRouter.createCaller({ logger })["cloudflare-ai"].accesses.permission;

const setPolicies = (policies: Policy[] = [ACCOUNT_GROUPS]) =>
  permission().setPoliciesForUser({
    context,
    policies,
    userBody: "p0_grant",
    userId: GRANT_REF,
  });

const deleteUser = () =>
  permission().deleteUser({ context, userBody: "p0_grant", userId: GRANT_REF });

/** The bodies Cloudflare was sent for `method` on `path`. */
const bodiesOf = (
  { cloudflare }: ReturnType<typeof fakeAccount>,
  method: string,
  path: string
) =>
  cloudflare
    .calls()
    .flatMap((sent, index) =>
      sent === `${method} ${CLOUDFLARE_API}${path}`
        ? [cloudflare.body(index)]
        : []
    );

stubToken();

beforeEach(() => {
  events.length = 0;
  store.clear();
  secrets.clear();
  writes.fail = false;
});

describe("setPoliciesForUser", () => {
  it("mints a token named after the secret when there is none, and stores its value", async () => {
    const account = fakeAccount();

    await setPolicies();

    expect(bodiesOf(account, "POST", `${ACCOUNT}/tokens`)).toEqual([
      {
        expires_on: EXPIRES_ON,
        name: TOKEN_NAME,
        policies: [
          {
            effect: "allow",
            permission_groups: [{ id: "dns-read" }],
            resources: { [ACCOUNT_KEY]: "*" },
          },
        ],
      },
    ]);
    expect(store.get(GRANT_REF)).toBe("value-minted-1");
    expect(events).toEqual(["mint minted-1", "write secret"]);
  });

  it("changes the one token in place and leaves the secret", async () => {
    const account = fakeAccount({
      tokens: [
        { id: "own", name: "customer token" },
        { id: "other-grant", name: "P0 arn:secret:other" },
        { id: "t-1", name: TOKEN_NAME },
      ],
    });

    await setPolicies();

    expect(bodiesOf(account, "PUT", `${ACCOUNT}/tokens/t-1`)).toEqual([
      {
        expires_on: EXPIRES_ON,
        name: TOKEN_NAME,
        policies: [
          {
            effect: "allow",
            permission_groups: [{ id: "dns-read" }],
            resources: { [ACCOUNT_KEY]: "*" },
          },
        ],
        status: "active",
      },
    ]);
    expect(events).toEqual(["update t-1"]);
  });

  it("mints and stores a new token before it deletes duplicates", async () => {
    fakeAccount({
      tokens: [
        { id: "t-1", name: TOKEN_NAME },
        { id: "t-2", name: TOKEN_NAME },
      ],
    });

    await setPolicies();

    expect(events).toEqual([
      "mint minted-1",
      "write secret",
      "delete t-1",
      "delete t-2",
    ]);
    expect(store.get(GRANT_REF)).toBe("value-minted-1");
  });

  it("deletes every token with the name when no resources remain", async () => {
    const account = fakeAccount({
      tokens: [
        { id: "own", name: "customer token" },
        { id: "t-1", name: TOKEN_NAME },
        { id: "t-2", name: TOKEN_NAME },
      ],
    });

    await setPolicies([REVOKE]);

    expect(events).toEqual(["delete t-1", "delete t-2"]);
    expect(account.state.tokens).toEqual([
      { id: "own", name: "customer token" },
    ]);
  });

  it("does nothing when no resources remain and there is no token", async () => {
    const account = fakeAccount();

    await setPolicies([REVOKE]);

    expect(events).toEqual([]);
    expect(account.cloudflare.calls()).toHaveLength(1);
  });

  it("finds zone ids by name, and lists zones only for a zone resource", async () => {
    const account = fakeAccount({
      zones: [{ id: "zone-1", name: "example.com" }],
    });

    await setPolicies([
      {
        expiresOn: EXPIRES_ON,
        resources: [
          { groups: ["dns-edit"], scope: "zone", zone: "example.com" },
        ],
      },
    ]);

    expect(bodiesOf(account, "POST", `${ACCOUNT}/tokens`)).toMatchObject([
      {
        policies: [
          {
            resources: {
              [ACCOUNT_KEY]: { "com.cloudflare.api.zone.zone-1": "*" },
            },
          },
        ],
      },
    ]);

    const noZones = fakeAccount();
    await setPolicies();
    expect(
      noZones.cloudflare.calls().some((call) => call.includes("/zones"))
    ).toBe(false);
  });

  it("leaves out a zone the account no longer has, and warns", async () => {
    const log = recordLogger();
    const account = fakeAccount({
      tokens: [{ id: "t-1", name: TOKEN_NAME }],
    });

    await setPolicies([
      {
        expiresOn: EXPIRES_ON,
        resources: [
          { groups: ["dns-read"], scope: "account" },
          { groups: ["dns-edit"], scope: "zone", zone: "gone.example" },
        ],
      },
    ]);

    expect(bodiesOf(account, "PUT", `${ACCOUNT}/tokens/t-1`)).toMatchObject([
      { policies: [{ resources: { [ACCOUNT_KEY]: "*" } }] },
    ]);
    expect(log.lines()).toContainEqual([
      { missingZones: ["gone.example"] },
      "left out the resources of zones the account no longer has",
    ]);
    vi.mocked(logger.child).mockRestore();
  });

  it("deletes the token when its only zone is gone", async () => {
    fakeAccount({ tokens: [{ id: "t-1", name: TOKEN_NAME }] });

    await setPolicies([
      {
        expiresOn: EXPIRES_ON,
        resources: [
          { groups: ["dns-edit"], scope: "zone", zone: "gone.example" },
        ],
      },
    ]);

    expect(events).toEqual(["delete t-1"]);
  });

  it("deletes the token it minted when the secret can't be written", async () => {
    const account = fakeAccount();
    writes.fail = true;

    await expect(setPolicies()).rejects.toThrow("write failed");

    expect(events).toEqual(["mint minted-1", "delete minted-1"]);
    expect(account.state.tokens).toEqual([]);
  });

  it("still fails with the write's error when the cleanup delete fails too", async () => {
    const account = fakeAccount();
    account.state.failDelete.add("minted-1");
    writes.fail = true;

    await expect(setPolicies()).rejects.toThrow("write failed");

    expect(account.state.tokens).toEqual([
      { id: "minted-1", name: TOKEN_NAME },
    ]);
  });

  it("shows the cap error on a mint at the account's token limit", async () => {
    const account = fakeAccount();
    account.state.mintFails = () =>
      failed(403, [
        {
          code: 1001,
          message: "You have reached the maximum number of API tokens",
        },
      ]);

    const { data } = await connectorError(() => setPolicies());

    expect(data).toMatchObject({
      message: TOKEN_CAP_MESSAGE,
      type: "validation_error",
    });
    expect(store.has(GRANT_REF)).toBe(false);
  });

  it("refuses more than one policy as a control-plane bug", async () => {
    fakeAccount();

    const { data } = await connectorError(() =>
      setPolicies([ACCOUNT_GROUPS, ACCOUNT_GROUPS])
    );

    expect(data).toMatchObject({ payload: { nPolicies: 2 }, type: "unknown" });
    expect(events).toEqual([]);
  });

  it("refuses an expiry with a fraction of a second", async () => {
    fakeAccount();

    await expect(
      setPolicies([
        { ...ACCOUNT_GROUPS, expiresOn: "2026-11-05T12:00:00.000Z" },
      ])
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  describe("a rerun after a failed step", () => {
    it("mints again after a failed mint", async () => {
      const account = fakeAccount();
      account.state.mintFails = () =>
        failed(500, [{ code: 1, message: "down" }]);

      await expect(setPolicies()).rejects.toMatchObject({
        data: { type: "upstream_unavailable" },
      });
      await setPolicies();

      expect(events).toEqual(["mint failed", "mint minted-1", "write secret"]);
      expect(store.get(GRANT_REF)).toBe("value-minted-1");
    });

    it("mints again after a failed secret write", async () => {
      fakeAccount();
      writes.fail = true;

      await expect(setPolicies()).rejects.toThrow("write failed");
      writes.fail = false;
      await setPolicies();

      expect(events).toEqual([
        "mint minted-1",
        "delete minted-1",
        "mint minted-2",
        "write secret",
      ]);
      expect(store.get(GRANT_REF)).toBe("value-minted-2");
    });

    // The accepted risk of spec section 8: the token stays, with no value
    // in the secret, until the last revoke or its expiry.
    it("changes the left token in place after a failed write and a failed cleanup", async () => {
      const account = fakeAccount();
      account.state.failDelete.add("minted-1");
      writes.fail = true;

      await expect(setPolicies()).rejects.toThrow("write failed");
      writes.fail = false;
      await setPolicies();

      expect(events).toEqual(["mint minted-1", "update minted-1"]);
      expect(store.has(GRANT_REF)).toBe(false);
    });

    it("changes the token again after a failed PUT", async () => {
      const account = fakeAccount({
        tokens: [{ id: "t-1", name: TOKEN_NAME }],
      });
      account.state.failUpdate.add("t-1");

      await expect(setPolicies()).rejects.toMatchObject({
        data: { type: "upstream_unavailable" },
      });
      account.state.failUpdate.delete("t-1");
      await setPolicies();

      expect(events).toEqual(["update t-1"]);
    });

    it("keeps a valid token in the secret when a duplicate's delete fails, and clears the duplicates on the rerun", async () => {
      const account = fakeAccount({
        tokens: [
          { id: "t-1", name: TOKEN_NAME },
          { id: "t-2", name: TOKEN_NAME },
        ],
      });
      account.state.failDelete.add("t-2");

      await expect(setPolicies()).rejects.toMatchObject({
        data: { type: "upstream_unavailable" },
      });
      expect(store.get(GRANT_REF)).toBe("value-minted-1");

      account.state.failDelete.delete("t-2");
      await setPolicies();

      expect(events).toEqual([
        "mint minted-1",
        "write secret",
        "delete t-1",
        "mint minted-2",
        "write secret",
        "delete t-2",
        "delete minted-1",
      ]);
      expect(account.state.tokens).toEqual([
        { id: "minted-2", name: TOKEN_NAME },
      ]);
      expect(store.get(GRANT_REF)).toBe("value-minted-2");
    });
  });
});

describe("provisionUser", () => {
  it("gives the same user id for a new and an existing secret", async () => {
    const provision = () =>
      permission().provisionUser({ context, userBody: "grant" });

    const created = await provision();
    const found = await provision();

    expect(created).toBe(GRANT_REF);
    expect(found).toBe(GRANT_REF);
  });
});

describe("deleteUser", () => {
  it("deletes every token with the name, then the secret", async () => {
    const account = fakeAccount({
      tokens: [
        { id: "own", name: "customer token" },
        { id: "t-1", name: TOKEN_NAME },
        { id: "t-2", name: TOKEN_NAME },
      ],
    });
    store.set(GRANT_REF, "value");

    await deleteUser();

    expect(events).toEqual(["delete t-1", "delete t-2", "delete secret"]);
    expect(account.state.tokens).toEqual([
      { id: "own", name: "customer token" },
    ]);
  });

  it("deletes the secret when there is no token", async () => {
    fakeAccount();

    await deleteUser();

    expect(events).toEqual(["delete secret"]);
  });

  it("keeps the secret when a token can't be deleted, and finishes on the rerun", async () => {
    const account = fakeAccount({
      tokens: [
        { id: "t-1", name: TOKEN_NAME },
        { id: "t-2", name: TOKEN_NAME },
      ],
    });
    store.set(GRANT_REF, "value");
    account.state.failDelete.add("t-2");

    await expect(deleteUser()).rejects.toMatchObject({
      data: { type: "upstream_unavailable" },
    });
    expect(store.has(GRANT_REF)).toBe(true);

    account.state.failDelete.delete("t-2");
    await deleteUser();

    expect(events).toEqual(["delete t-1", "delete t-2", "delete secret"]);
  });
});
