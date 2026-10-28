import type { Logger } from "@p0security/connector";
import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  SITE,
  connectorErrorOf,
  withoutWaits,
} from "../../../__tests__/fixtures.ts";
import type { FakeSecretManager } from "../../../__tests__/secret-manager-mock.ts";
import { REQUEST_BUDGET_MS } from "../../../jira/atlassian-call.ts";
import { t } from "../../../router.ts";
import { router } from "../handler.ts";

const vault = vi.hoisted((): { fake?: FakeSecretManager } => ({}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  const { fakeSecretManager } =
    await import("../../../__tests__/secret-manager-mock.ts");
  const fake = fakeSecretManager(actual);
  vault.fake = fake;
  return {
    ...actual,
    createSecretManagerClient: fake.createSecretManagerClient,
  };
});

const fakeVault = () => {
  if (vault.fake === undefined)
    throw new Error("the secret manager isn't mocked");
  return vault.fake;
};

const NAME = "p0-jira-ai-r-1";
const KEY = `acme-vault/${NAME}`;
const POOL_KEY = "acme-vault/jira-pool-1";

const context = {
  requestId: "r-1",
  site: SITE,
  vault: { projectId: "acme-vault" },
  poolSecret: {
    manager: "gcp" as const,
    projectId: "acme-vault",
    secretId: "jira-pool-1",
  },
};

// Everything the connector logs, to check that no credential is in it.
let logged = "";
const recordingLogger = (): Logger => {
  const record =
    () =>
    (...args: unknown[]) => {
      logged += JSON.stringify(args);
    };
  const self = {
    debug: record(),
    info: record(),
    warn: record(),
    error: record(),
    child: () => self,
  };
  return self as unknown as Logger;
};
const logger = recordingLogger();

const caller = () => router(t).createCaller({ logger });

const fetchMock = vi.fn(async (url: string) => {
  throw new Error(`unexpected call to ${url}`);
});

beforeEach(() => {
  logged = "";
  const { secrets, failures, readDelay } = fakeVault();
  secrets.clear();
  failures.clear();
  readDelay.ms = 0;
  secrets.set(POOL_KEY, "pool-api-key-1");
  fetchMock.mockClear();
  vi.stubGlobal("fetch", fetchMock);
});

const grant = async () => {
  const userId = await caller().provisionUser({ userBody: NAME, context });
  await caller().setPoliciesForUser({
    userId,
    userBody: userId,
    policies: [{ accountId: "pool-acc-1" }],
    context,
  });
  return userId;
};

describe("grant", () => {
  it("creates the request's secret and copies the pool account's API key into it", async () => {
    await expect(grant()).resolves.toBe(NAME);

    expect(fakeVault().secrets.get(KEY)).toBe("pool-api-key-1");
  });

  it("calls nothing outside the secret manager", async () => {
    await grant();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("copies the key the pool secret holds now, on every grant", async () => {
    await grant();
    fakeVault().secrets.set(POOL_KEY, "pool-api-key-2");
    await grant();

    expect(fakeVault().secrets.get(KEY)).toBe("pool-api-key-2");
  });

  it("reuses a secret a retried grant already created", async () => {
    fakeVault().secrets.set(KEY, undefined);

    await expect(
      caller().provisionUser({ userBody: NAME, context })
    ).resolves.toBe(NAME);
  });

  it("does nothing when no policy remains", async () => {
    fakeVault().secrets.set(KEY, "pool-api-key-0");

    await caller().setPoliciesForUser({
      userId: NAME,
      userBody: NAME,
      policies: [],
      context,
    });

    expect(fakeVault().secrets.get(KEY)).toBe("pool-api-key-0");
  });

  it("refuses more than one pool account, and writes nothing", async () => {
    fakeVault().secrets.set(KEY, undefined);

    await expect(
      caller().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ accountId: "a" }, { accountId: "b" }],
        context,
      })
    ).rejects.toMatchObject({ data: { type: "unknown" } });
    expect(fakeVault().secrets.get(KEY)).toBeUndefined();
  });

  it("neither returns nor logs the API key", async () => {
    const userId = await grant();

    expect(userId).toBe(NAME);
    expect(logged).not.toBe("");
    expect(logged).not.toContain("pool-api-key");
  });

  it("keeps the secret's name out of a failure to read the pool secret", async () => {
    fakeVault().secrets.delete(POOL_KEY);
    fakeVault().secrets.set(KEY, undefined);

    const error = await connectorErrorOf(
      caller().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ accountId: "pool-acc-1" }],
        context,
      })
    );

    expect(error.data.type).toBe("object_not_found");
    expect(JSON.stringify(error.data)).not.toContain("jira-pool-1");
  });

  it("fails with validation_error for an empty pool secret, and writes nothing", async () => {
    fakeVault().secrets.set(POOL_KEY, " \n");
    fakeVault().secrets.set(KEY, undefined);

    await expect(
      caller().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ accountId: "pool-acc-1" }],
        context,
      })
    ).rejects.toMatchObject({
      data: {
        type: "validation_error",
        message:
          "The pool account's API key in Google Secret Manager is empty. Add a new version of the secret whose whole value is the pool account's API key.",
      },
    });
    expect(fakeVault().secrets.get(KEY)).toBeUndefined();
  });

  it("stops waiting for the pool account's API key when the request's budget runs out", async () => {
    fakeVault().secrets.set(KEY, undefined);
    // The read would succeed, but only after the budget.
    fakeVault().readDelay.ms = REQUEST_BUDGET_MS + 5_000;

    const error = await withoutWaits(() =>
      connectorErrorOf(
        caller().setPoliciesForUser({
          userId: NAME,
          userBody: NAME,
          policies: [{ accountId: "pool-acc-1" }],
          context,
        })
      )
    );

    expect(error.data.type).toBe("upstream_unavailable");
    expect(error.message).toBe(
      "Google Secret Manager didn't return the pool account's API key in time. Try the request again in a few minutes."
    );
    expect(fakeVault().secrets.get(KEY)).toBeUndefined();
  });

  it("maps a refused vault write to insufficient_privileges", async () => {
    const { failures, secrets } = fakeVault();
    secrets.set(KEY, undefined);
    const actual = await vi.importActual<typeof SecretManagerClientModule>(
      "@p0security/secret-manager-client"
    );
    failures.set("createSecretVersion", new actual.UnauthorizedError("gcp"));

    await expect(
      caller().setPoliciesForUser({
        userId: NAME,
        userBody: NAME,
        policies: [{ accountId: "pool-acc-1" }],
        context,
      })
    ).rejects.toMatchObject({ data: { type: "insufficient_privileges" } });
  });
});

describe("identifyUser", () => {
  it("returns the secret's name when it exists, else null", async () => {
    await expect(
      caller().identifyUser({ userBody: NAME, context })
    ).resolves.toBeNull();

    fakeVault().secrets.set(KEY, undefined);

    await expect(
      caller().identifyUser({ userBody: NAME, context })
    ).resolves.toBe(NAME);
  });
});

describe("revoke", () => {
  it("deletes the request's secret", async () => {
    await grant();

    await caller().deleteUser({ userId: NAME, userBody: NAME, context });

    expect(fakeVault().secrets.has(KEY)).toBe(false);
  });

  it("treats a secret that is already gone as deleted", async () => {
    await expect(
      caller().deleteUser({ userId: NAME, userBody: NAME, context })
    ).resolves.toBeNull();
  });

  it("deletes only its own request's secret, and leaves the pool secret", async () => {
    await grant();
    fakeVault().secrets.set("acme-vault/p0-jira-ai-r-2", "other-key");

    await caller().deleteUser({ userId: NAME, userBody: NAME, context });

    expect(fakeVault().secrets.get("acme-vault/p0-jira-ai-r-2")).toBe(
      "other-key"
    );
    expect(fakeVault().secrets.get(POOL_KEY)).toBe("pool-api-key-1");
  });
});
