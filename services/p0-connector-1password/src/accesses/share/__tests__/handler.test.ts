import type { ItemOverview } from "@1password/sdk";
import { ConnectorError, createLogger } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  RateLimitExceededError,
  SHARING_POLICY,
  fakeItem,
  newFakeOnePassword,
} from "../../../__tests__/fake-one-password.ts";
import { CREDENTIALS, ITEM, VAULT } from "../../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
} from "../../../__tests__/helpers.ts";
import { newVaultReader } from "../../../onepassword/vault.ts";
import {
  type ConnectVault,
  type ListAccountVaults,
  newSharePrimitives,
} from "../handler.ts";

// A field's value, which the SDK's item overview never carries but a careless
// mapping of a full item would.
const FIELD_VALUE = "SENTINEL-field-value-4b1d";

/** An overview with more on it than the SDK promises, as a later SDK might. */
const itemWithFields = (id: string, title: string): ItemOverview =>
  Object.assign(fakeItem(id, title), {
    fields: [{ id: "password", value: FIELD_VALUE }],
    notes: FIELD_VALUE,
  });

const fakeWith = (items: ItemOverview[]) =>
  newFakeOnePassword({
    vaults: new Map([[VAULT, "Engineering"]]),
    items: new Map([[VAULT, items]]),
    policy: SHARING_POLICY,
  });

let fake = fakeWith([]);
const connect = vi.fn<ConnectVault>(async ({ vault }) =>
  newVaultReader(fake.asClient(), vault)
);

const listAccount = vi.fn<ListAccountVaults>(async () => [
  { id: VAULT, title: "Engineering" },
  { id: "q7ptfwa4xmjd2vlb6rcn3ozuhe", title: "Finance" },
]);

const list = (
  query: Parameters<ReturnType<typeof newSharePrimitives>["list"]>[0],
  logger = createLogger()
) => newSharePrimitives(logger, connect, listAccount).list(query);

beforeEach(() => {
  vi.clearAllMocks();
  fake = fakeWith([
    itemWithFields(ITEM, "Prod database"),
    itemWithFields("j5hbqmr7nz3uqbnkwqqyvkqqjm", "Deploy key"),
  ]);
});

describe("list vaults", () => {
  const context = { tokenSecret: CREDENTIALS.tokenSecret };

  it("answers each vault the service account sees as its ID and title", async () => {
    await expect(list({ type: "vaults", context })).resolves.toEqual([
      { key: VAULT, value: "Engineering" },
      { key: "q7ptfwa4xmjd2vlb6rcn3ozuhe", value: "Finance" },
    ]);
    expect(listAccount).toHaveBeenCalledWith(context);
  });

  it("logs how many vaults there are, never their titles", async () => {
    const { log, info } = newRecordingLogger();

    await list({ type: "vaults", context }, log);

    expect(info).toHaveBeenCalledWith(
      { count: 2 },
      "listed the account's vaults"
    );
    expect(JSON.stringify(info.mock.calls)).not.toContain("Finance");
  });

  it("never repeats the SDK's message", async () => {
    listAccount.mockRejectedValueOnce(new Error(`no access to ${FIELD_VALUE}`));

    await expect(
      connectorError(() => list({ type: "vaults", context }))
    ).resolves.toEqual({
      type: "unknown",
      message: "1Password failed the connector's call.",
      payload: {},
    });
  });
});

describe("list items", () => {
  it("answers each active item as its ID, title and category", async () => {
    await expect(
      list({ type: "items", context: CREDENTIALS })
    ).resolves.toEqual([
      { key: ITEM, value: "Prod database", group: "Login" },
      {
        key: "j5hbqmr7nz3uqbnkwqqyvkqqjm",
        value: "Deploy key",
        group: "Login",
      },
    ]);
    expect(connect).toHaveBeenCalledWith(CREDENTIALS);
    expect(fake.client.items.list).toHaveBeenCalledWith(VAULT, {
      type: "ByState",
      content: { active: true, archived: false },
    });
  });

  it("never answers with anything an item carries besides those", async () => {
    const answer = await list({ type: "items", context: CREDENTIALS });

    expect(JSON.stringify(answer)).not.toContain(FIELD_VALUE);
  });

  it("logs how many items there are, never their titles", async () => {
    const { log, info, warn, error } = newRecordingLogger();

    await list({ type: "items", context: CREDENTIALS }, log);

    expect(info).toHaveBeenCalledWith({ count: 2 }, "listed the vault's items");
    const logged = JSON.stringify([
      info.mock.calls,
      warn.mock.calls,
      error.mock.calls,
    ]);
    expect(logged).not.toContain("Prod database");
    expect(logged).not.toContain(FIELD_VALUE);
  });

  it("answers an empty vault with no items", async () => {
    fake = fakeWith([]);

    await expect(
      list({ type: "items", context: CREDENTIALS })
    ).resolves.toEqual([]);
  });
});

describe("read the sharing policy", () => {
  it("answers one item per field, the lists comma-joined", async () => {
    await expect(
      list({ type: "sharing-policy", context: CREDENTIALS, itemId: ITEM })
    ).resolves.toEqual([
      { key: "maxExpiry", value: "ThirtyDays" },
      { key: "defaultExpiry", value: "SevenDays" },
      { key: "allowedRecipientTypes", value: "Email,Domain" },
      { key: "allowedTypes", value: "Authenticated,Public" },
    ]);
    expect(fake.client.items.shares.getAccountPolicy).toHaveBeenCalledWith(
      VAULT,
      ITEM
    );
  });
});

describe("a failed listing", () => {
  it("passes the connector's own errors through, such as an unreadable secret", async () => {
    const unreadable = new ConnectorError({
      type: "object_not_found",
      message: "The connector couldn't find the secret.",
      payload: { query: "op-token", manager: "aws" },
    });
    connect.mockRejectedValueOnce(unreadable);

    await expect(
      connectorError(() => list({ type: "items", context: CREDENTIALS }))
    ).resolves.toEqual(unreadable.data);
  });

  it("says when 1Password is rate limiting", async () => {
    fake.client.items.list.mockRejectedValue(
      new RateLimitExceededError("slow")
    );

    await expect(
      connectorError(() => list({ type: "items", context: CREDENTIALS }))
    ).resolves.toMatchObject({ type: "rate_limited" });
  });

  it("never repeats the SDK's message", async () => {
    fake.client.items.shares.getAccountPolicy.mockRejectedValue(
      new Error(`no access to ${FIELD_VALUE}`)
    );

    const data = await connectorError(() =>
      list({ type: "sharing-policy", context: CREDENTIALS, itemId: ITEM })
    );

    expect(data).toEqual({
      type: "unknown",
      message: "1Password failed the connector's call.",
      payload: { vault: VAULT },
    });
  });
});

describe("the user primitives", () => {
  const primitives = newSharePrimitives(createLogger(), connect);
  const context = { ...CREDENTIALS, requestId: "req-1" };

  // A share goes to an email, not to a 1Password account.
  it("takes the email as the user, without calling 1Password", async () => {
    await expect(primitives.getUser(context, "alice@acme.com")).resolves.toBe(
      "alice@acme.com"
    );
    await expect(
      primitives.createUser(context, "alice@acme.com")
    ).resolves.toBe("alice@acme.com");
    expect(connect).not.toHaveBeenCalled();
  });

  it("leaves the perimeter's own user check off", () => {
    expect(primitives.validation(context as never)).toEqual({ user: null });
  });

  it("changes nothing in 1Password to grant or revoke", async () => {
    await primitives.setPoliciesForUser(
      context,
      "alice@acme.com",
      "alice@acme.com",
      [{}]
    );
    await primitives.deleteUser(context, "alice@acme.com", "alice@acme.com");

    expect(connect).not.toHaveBeenCalled();
  });
});
