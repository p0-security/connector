import { ConnectorError, createLogger } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AuthExpiredError,
  type FakeOnePassword,
  RateLimitExceededError,
  SHARING_POLICY,
  fakeItem,
  newFakeOnePassword,
} from "../../__tests__/fake-one-password.ts";
import {
  ALLOWED_PATTERN,
  AWS_SECRET,
  LOAD_TIMEOUT_MS,
  TOKEN,
  VAULT,
} from "../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
  thrown,
} from "../../__tests__/helpers.ts";
import { connectorRouter } from "../../router.ts";
import { checkOnePassword } from "../handler.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token, or fails, as each test says. `vi.hoisted` keeps it the
// same mock across `vi.resetModules`.
const getServiceAccountToken = vi.hoisted(() => vi.fn());
vi.mock("../../secrets.ts", () => ({ getServiceAccountToken }));

// The SDK's client, which signs in with whatever token it's given.
const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("@1password/sdk", () => sdk);

/** A vault the service account sees with no active item. */
const EMPTY_VAULT = "q7ptfwa4xmjd2vlb6rcn3ozuhe";

/** An install's credentials: where the account's token is, and no vault. */
const ACCOUNT = { tokenSecret: AWS_SECRET };

const fakeWith = (overrides: Partial<FakeOnePassword["state"]> = {}) =>
  newFakeOnePassword({
    vaults: new Map([
      [EMPTY_VAULT, "Empty"],
      [VAULT, "Engineering"],
    ]),
    items: new Map([[VAULT, [fakeItem("item-1", "Prod database")]]]),
    policy: SHARING_POLICY,
    ...overrides,
  });

const logger = createLogger();

// Each test signs in afresh: the client is cached per secret version.
let versions = 0;

const validate = (input: unknown = ACCOUNT) =>
  connectorRouter
    .createCaller({ logger })
    ["1password"].install.validation.get(input as typeof ACCOUNT);

let fake: FakeOnePassword;

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);
  getServiceAccountToken.mockImplementation(async () => ({
    token: TOKEN,
    version: `op-token/versions/${++versions}`,
  }));
  fake = fakeWith();
  sdk.createClient.mockImplementation(async () => fake.asClient());
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("install validation", () => {
  it("reports how many vaults the account sees, that sharing was checked, and the pattern", async () => {
    await expect(validate()).resolves.toEqual({
      vaultCount: 2,
      sharingChecked: true,
      allowedDomains: ALLOWED_PATTERN,
    });
    expect(sdk.createClient).toHaveBeenCalledWith(
      expect.objectContaining({ auth: TOKEN, integrationName: "P0 Security" })
    );
  });

  // The first vault 1Password lists has no item, so the policy is read
  // through the next vault's.
  it("reads the sharing policy through the first active item of any vault", async () => {
    await validate();

    expect(fake.client.items.list).toHaveBeenCalledWith(EMPTY_VAULT, {
      type: "ByState",
      content: { active: true, archived: false },
    });
    expect(fake.client.items.shares.getAccountPolicy).toHaveBeenCalledWith(
      VAULT,
      "item-1"
    );
  });

  it("signs in once per secret version", async () => {
    getServiceAccountToken.mockResolvedValue({
      token: TOKEN,
      version: "op-token/versions/fixed",
    });

    await validate();
    await validate();

    expect(sdk.createClient).toHaveBeenCalledTimes(1);
  });

  it("refuses a pointer that isn't one, before reading anything", async () => {
    await expect(validate({ tokenSecret: TOKEN })).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    expect(getServiceAccountToken).not.toHaveBeenCalled();
  });

  describe("fails at", () => {
    it("`secret` when the token can't be read", async () => {
      getServiceAccountToken.mockRejectedValue(
        new ConnectorError({
          type: "object_not_found",
          message: "The connector couldn't find the secret.",
          payload: { query: "op-token", manager: "aws" },
        })
      );

      await expect(connectorError(validate)).resolves.toMatchObject({
        type: "object_not_found",
        message: "The connector couldn't find the secret.",
        payload: { step: "secret", query: "op-token" },
      });
      expect(sdk.createClient).not.toHaveBeenCalled();
    });

    it("`authenticate` when 1Password refuses the token, in the connector's words", async () => {
      sdk.createClient.mockRejectedValue(
        new Error(`invalid service account token ${TOKEN}`)
      );

      const data = await connectorError(validate);

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({ step: "authenticate" });
      expect(data.message).toBe(
        "1Password didn't accept the token in op-token. Check that it holds the account's service account token, which starts with ops_, and that the service account is active."
      );
      expect(JSON.stringify(data)).not.toContain(TOKEN);
    });

    it("`authenticate` with a rate limit, saying so", async () => {
      sdk.createClient.mockRejectedValue(new RateLimitExceededError("slow"));

      await expect(connectorError(validate)).resolves.toMatchObject({
        type: "rate_limited",
        payload: { step: "authenticate" },
      });
    });

    it("`authenticate` again on the next call, after a failed sign-in", async () => {
      getServiceAccountToken.mockResolvedValue({
        token: TOKEN,
        version: "op-token/versions/retry",
      });
      sdk.createClient.mockRejectedValueOnce(new Error("refused"));

      await expect(validate()).rejects.toThrow();
      await expect(validate()).resolves.toMatchObject({ sharingChecked: true });
      expect(sdk.createClient).toHaveBeenCalledTimes(2);
    });

    // It loads the router afresh, which a busy machine can take seconds over.
    it(
      "`domains` when the connector has no usable pattern",
      async () => {
        vi.stubEnv("DOMAIN_ALLOW_PATTERN", "");
        // The pattern is parsed once per process, as a deployment's is.
        vi.resetModules();
        const { connectorRouter: fresh } = await import("../../router.ts");

        // A `ConnectorError` from the fresh modules, which `instanceof` this
        // file's class can't recognize.
        const error = await thrown(() =>
          fresh
            .createCaller({ logger })
            ["1password"].install.validation.get(ACCOUNT)
        );

        expect(error).toMatchObject({
          data: {
            type: "validation_error",
            message: expect.stringContaining("DOMAIN_ALLOW_PATTERN"),
            payload: { step: "domains" },
          },
        });
      },
      LOAD_TIMEOUT_MS
    );
  });
});

describe("checkOnePassword", () => {
  const check = (client = fake.asClient(), log = logger) =>
    checkOnePassword({ client, logger: log });

  it("fails at `vaults` when the service account sees no vault", async () => {
    fake = fakeWith({ vaults: new Map() });

    await expect(connectorError(() => check())).resolves.toEqual({
      type: "validation_error",
      message:
        "The service account can't see any vault. In 1Password, give it Read Items and Share Items on each vault people may request items from.",
      payload: { step: "vaults" },
    });
    expect(fake.client.items.list).not.toHaveBeenCalled();
  });

  it("fails at `vaults` when 1Password won't list them, in the connector's words", async () => {
    fake.client.vaults.list.mockRejectedValue(new Error("forbidden"));

    await expect(connectorError(() => check())).resolves.toEqual({
      type: "insufficient_privileges",
      message:
        "P0 couldn't list the vaults the service account can see. Check that the service account is active.",
      payload: { step: "vaults" },
    });
  });

  it("fails at `vaults` with an expired token, saying so", async () => {
    fake.client.vaults.list.mockRejectedValue(new AuthExpiredError("expired"));

    await expect(connectorError(() => check())).resolves.toMatchObject({
      type: "insufficient_privileges",
      payload: { step: "vaults" },
    });
  });

  it("skips `sharing` with a warning when no vault has an active item", async () => {
    fake = fakeWith({ items: new Map() });
    const { log, warn } = newRecordingLogger();

    await expect(check(fake.asClient(), log)).resolves.toEqual({
      vaultCount: 2,
      sharingChecked: false,
    });
    expect(warn).toHaveBeenCalledWith(
      { vaults: 2 },
      expect.stringContaining("skipped the sharing check")
    );
    expect(fake.client.items.shares.getAccountPolicy).not.toHaveBeenCalled();
  });

  it.each([
    [
      "public links only",
      { allowedTypes: ["Public"], allowedRecipientTypes: ["Email"] },
    ],
    [
      "domain recipients only",
      { allowedTypes: ["Authenticated"], allowedRecipientTypes: ["Domain"] },
    ],
    ["no sharing", { allowedTypes: [], allowedRecipientTypes: [] }],
  ])(
    "fails at `sharing` for a policy that allows %s",
    async (_case, policy) => {
      fake = fakeWith({ policy: { ...SHARING_POLICY, ...policy } as never });

      await expect(connectorError(() => check())).resolves.toEqual({
        type: "validation_error",
        message:
          "1Password's item sharing policy doesn't allow sharing an item with a specific person by email. Ask a 1Password owner or administrator to allow it.",
        payload: { step: "sharing" },
      });
    }
  );

  it.each([
    ["list a vault's items", "list"],
    ["read the sharing policy", "getAccountPolicy"],
  ] as const)("fails at `sharing` when it can't %s", async (_case, call) => {
    const failing =
      call === "list"
        ? fake.client.items.list
        : fake.client.items.shares.getAccountPolicy;
    failing.mockRejectedValue(new Error("forbidden"));

    await expect(connectorError(() => check())).resolves.toEqual({
      type: "insufficient_privileges",
      message:
        "P0 couldn't read 1Password's item sharing policy. Check that the service account has Read Items and Share Items on its vaults.",
      payload: { step: "sharing" },
    });
  });

  it("never logs a vault's or an item's title", async () => {
    const { log, info, warn, error } = newRecordingLogger();

    await check(fake.asClient(), log);

    const logged = JSON.stringify([
      info.mock.calls,
      warn.mock.calls,
      error.mock.calls,
    ]);
    expect(logged).not.toContain("Prod database");
    expect(logged).not.toContain("Engineering");
  });
});
