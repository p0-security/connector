import { ConnectorError, createLogger } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeOnePassword,
  LINK,
  RateLimitExceededError,
  SHARING_POLICY,
  fakeItem,
  newFakeOnePassword,
} from "../../__tests__/fake-one-password.ts";
import {
  ALLOWED_PATTERN,
  AWS_SECRET,
  CREDENTIALS,
  EMAIL,
  ITEM,
  VAULT,
} from "../../__tests__/fixtures.ts";
import { connectorError } from "../../__tests__/helpers.ts";
import { SHARE_DURATIONS, type ShareInput } from "../definition.ts";
import { createShare, isWithin } from "../handler.ts";

// When the connector asked: 2026-10-15T00:00:00.000Z.
const NOW = Date.UTC(2026, 9, 15);

const INPUT: ShareInput = {
  ...CREDENTIALS,
  itemId: ITEM,
  email: EMAIL,
  expireAfter: "OneDay",
  oneTimeOnly: false,
};

let fake: FakeOnePassword;
const connect = vi.fn(async () => fake.asClient());

const share = (input: Partial<ShareInput> = {}) =>
  createShare(
    { ...INPUT, ...input },
    { connect, logger: createLogger(), now: () => NOW }
  );

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);
  fake = newFakeOnePassword({
    vaults: new Map([[VAULT, "Engineering"]]),
    items: new Map([[VAULT, [fakeItem(ITEM, "Prod database")]]]),
    policy: SHARING_POLICY,
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("createShare", () => {
  it("shares the item with the email only, for the duration asked", async () => {
    await expect(share()).resolves.toEqual({
      link: LINK,
      expiresAt: "2026-10-16T00:00:00.000Z",
      oneTimeOnly: false,
    });
    expect(connect).toHaveBeenCalledWith(AWS_SECRET);
    expect(fake.client.items.shares.validateRecipients).toHaveBeenCalledWith(
      SHARING_POLICY,
      [EMAIL]
    );
    expect(fake.client.items.shares.create).toHaveBeenCalledWith(
      expect.objectContaining({ id: ITEM }),
      SHARING_POLICY,
      {
        recipients: [{ type: "Email", parameters: { email: EMAIL } }],
        expireAfter: "OneDay",
        oneTimeOnly: false,
      }
    );
  });

  it("makes a link that opens once, when the account says so, and says so", async () => {
    await expect(share({ oneTimeOnly: true })).resolves.toMatchObject({
      oneTimeOnly: true,
    });
    expect(fake.client.items.shares.create).toHaveBeenCalledWith(
      expect.anything(),
      SHARING_POLICY,
      expect.objectContaining({ oneTimeOnly: true })
    );
  });

  it.each([
    ["OneHour", "2026-10-15T01:00:00.000Z"],
    ["OneDay", "2026-10-16T00:00:00.000Z"],
    ["SevenDays", "2026-10-22T00:00:00.000Z"],
    ["FourteenDays", "2026-10-29T00:00:00.000Z"],
    ["ThirtyDays", "2026-11-14T00:00:00.000Z"],
  ] as const)(
    "estimates a %s link's expiry from when it asked",
    async (expireAfter, expiresAt) => {
      await expect(share({ expireAfter })).resolves.toMatchObject({
        expiresAt,
      });
    }
  );

  it("refuses an email outside the allowed domains before calling 1Password", async () => {
    const data = await connectorError(() =>
      share({ email: "mallory@evil.com" })
    );

    expect(data).toEqual({
      type: "validation_error",
      message: `Your email domain isn't allowed for the 1Password vault ${VAULT}. Ask your P0 admin to check the connector's allowed domains.`,
      payload: {
        reason: "domain_not_allowed",
        vault: VAULT,
        email: "mallory@evil.com",
      },
    });
    expect(connect).not.toHaveBeenCalled();
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
  ])(
    "refuses when the policy allows %s, before making a link",
    async (_case, override) => {
      fake.state.policy = { ...SHARING_POLICY, ...override } as never;

      await expect(connectorError(() => share())).resolves.toEqual({
        type: "validation_error",
        message:
          "1Password's item sharing policy doesn't allow sharing an item with a specific person by email. Ask a 1Password owner or administrator to allow it.",
        payload: { reason: "sharing_policy", vault: VAULT, itemId: ITEM },
      });
      expect(fake.client.items.shares.create).not.toHaveBeenCalled();
      // Nor did it load the item's field values.
      expect(fake.client.items.get).not.toHaveBeenCalled();
    }
  );

  it("refuses a duration longer than the policy allows", async () => {
    fake.state.policy = { ...SHARING_POLICY, maxExpiry: "SevenDays" } as never;

    const data = await connectorError(() =>
      share({ expireAfter: "FourteenDays" })
    );

    expect(data).toEqual({
      type: "validation_error",
      message:
        "1Password's item sharing policy allows links that last up to SevenDays, shorter than the FourteenDays requested. Request a shorter duration, or ask a 1Password owner or administrator to allow longer links.",
      payload: {
        reason: "sharing_policy",
        vault: VAULT,
        itemId: ITEM,
        expireAfter: "FourteenDays",
        maxExpiry: "SevenDays",
      },
    });
    expect(fake.client.items.shares.create).not.toHaveBeenCalled();
    // Nor did it load the item's field values.
    expect(fake.client.items.get).not.toHaveBeenCalled();
  });

  it("allows a duration equal to the policy's longest", async () => {
    fake.state.policy = { ...SHARING_POLICY, maxExpiry: "SevenDays" } as never;

    await expect(share({ expireAfter: "SevenDays" })).resolves.toMatchObject({
      link: LINK,
    });
  });

  it.each([
    ["no recipient", []],
    [
      "a domain instead",
      [{ type: "Domain", parameters: { domain: "acme.com" } }],
    ],
    [
      "another email",
      [{ type: "Email", parameters: { email: "bob@acme.com" } }],
    ],
    [
      "a second recipient",
      [
        { type: "Email", parameters: { email: EMAIL } },
        { type: "Email", parameters: { email: "bob@acme.com" } },
      ],
    ],
  ])(
    "refuses when 1Password validates the email as %s",
    async (_case, recipients) => {
      fake.client.items.shares.validateRecipients.mockResolvedValue(
        recipients as never
      );

      await expect(connectorError(() => share())).resolves.toEqual({
        type: "validation_error",
        message: `1Password won't share an item with ${EMAIL} alone. Check that 1Password's item sharing policy allows sharing with this email.`,
        payload: {
          vault: VAULT,
          itemId: ITEM,
          email: EMAIL,
          recipients: recipients.length,
        },
      });
      expect(fake.client.items.shares.create).not.toHaveBeenCalled();
      // Nor did it load the item's field values.
      expect(fake.client.items.get).not.toHaveBeenCalled();
    }
  );

  // 1Password lowercases the recipient it validates.
  it("shares with an email 1Password hands back in lower case", async () => {
    fake.client.items.shares.validateRecipients.mockResolvedValue([
      { type: "Email", parameters: { email: "alice@acme.com" } },
    ] as never);

    await expect(share({ email: "Alice@Acme.com" })).resolves.toMatchObject({
      link: LINK,
    });
    expect(fake.client.items.shares.create).toHaveBeenCalledWith(
      expect.anything(),
      SHARING_POLICY,
      expect.objectContaining({
        recipients: [
          { type: "Email", parameters: { email: "alice@acme.com" } },
        ],
      })
    );
  });

  it("makes one attempt at the link, without retrying", async () => {
    fake.client.items.shares.create.mockRejectedValue(
      new RateLimitExceededError("slow")
    );

    await expect(connectorError(() => share())).resolves.toMatchObject({
      type: "rate_limited",
      payload: { vault: VAULT, itemId: ITEM },
    });
    expect(fake.client.items.shares.create).toHaveBeenCalledTimes(1);
  });

  it("fails a call 1Password fails in its own words, never the SDK's", async () => {
    fake.client.items.get.mockRejectedValue(new Error("item not found: abc"));

    await expect(connectorError(() => share())).resolves.toEqual({
      type: "unknown",
      message: "1Password failed the connector's call.",
      payload: { vault: VAULT, itemId: ITEM },
    });
  });

  it("passes the connector's own errors through, such as an unreadable secret", async () => {
    const unreadable = new ConnectorError({
      type: "insufficient_privileges",
      message: "The connector isn't allowed to read the secret.",
      payload: { secretId: "op-token", manager: "aws" },
    });
    connect.mockRejectedValueOnce(unreadable);

    await expect(connectorError(() => share())).resolves.toEqual(
      unreadable.data
    );
  });
});

describe("isWithin", () => {
  // Every pair, against the order 1Password documents.
  it.each(
    SHARE_DURATIONS.flatMap((duration, rank) =>
      SHARE_DURATIONS.map(
        (max, maxRank) => [duration, max, rank <= maxRank] as const
      )
    )
  )("takes %s within a %s maximum: %s", (duration, max, within) => {
    expect(isWithin(duration, max)).toBe(within);
  });

  it("takes nothing within a maximum it doesn't know", () => {
    expect(isWithin("OneHour", "Forever")).toBe(false);
  });
});
