import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT_ID,
  INSTALL_INPUT,
  NEVER_SHOWN,
  TOKEN,
  connectorError,
  logger,
  recordLogger,
  stubToken,
} from "../../__tests__/fixtures.ts";
import {
  failed,
  ok,
  stubCloudflare,
} from "../../cloudflare/__tests__/fake-cloudflare.ts";
import { CLOUDFLARE_API } from "../../cloudflare/cloudflare-api.ts";
import { connectorRouter } from "../../router.ts";
import { readToken } from "../../secrets.ts";
import { REQUIRED_GROUPS } from "../definition.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token, or fails, as each test says.
vi.mock("../../secrets.ts");

const ACCOUNT = `/accounts/${ACCOUNT_ID}`;
const ACCOUNT_KEY = `com.cloudflare.api.account.${ACCOUNT_ID}`;
const TOKEN_ID = "install-token-id";

const TOKENS_WRITE = {
  id: REQUIRED_GROUPS.accountApiTokensWrite.id,
  name: "Account API Tokens Write",
};
const ZONE_READ = { id: REQUIRED_GROUPS.zoneRead.id, name: "Zone Read" };

type Group = { id: string; name?: string };
type Resources = Record<string, unknown>;

const policy = (
  groups: Group[],
  resources: Resources = { [ACCOUNT_KEY]: "*" },
  effect: "allow" | "deny" = "allow"
) => ({ effect, id: "policy", permission_groups: groups, resources });

const ALL_ZONES = {
  [ACCOUNT_KEY]: { "com.cloudflare.api.account.zone.*": "*" },
};

/** The token as the dashboard makes it, from the setup steps. */
const INSTALL_POLICIES = [
  policy([TOKENS_WRITE]),
  policy([ZONE_READ], ALL_ZONES),
];

/** Cloudflare, answering verify and the token's own read. */
const cloudflareWith = ({
  policies = INSTALL_POLICIES,
  status = "active",
}: { policies?: unknown[]; status?: string } = {}) =>
  stubCloudflare({
    [`GET ${ACCOUNT}/tokens/verify`]: () => ok({ id: TOKEN_ID, status }),
    [`GET ${ACCOUNT}/tokens/${TOKEN_ID}`]: () =>
      ok({ id: TOKEN_ID, name: "P0 install", policies, status }),
  });

// Calling through the connector router also proves the `cloudflare-ai`
// namespace is registered with its install router.
const validate = (input: unknown = INSTALL_INPUT) => {
  const { install } = connectorRouter.createCaller({ logger })["cloudflare-ai"];
  // @ts-expect-error -- some tests send input that doesn't parse, on purpose.
  return install.validation.get(input);
};

stubToken();

describe("install validation", () => {
  it("reports the token after every check, reading only", async () => {
    const cloudflare = cloudflareWith();

    await expect(validate()).resolves.toStrictEqual({
      otherGroups: [],
      tokenId: TOKEN_ID,
    });

    expect(readToken).toHaveBeenCalledWith(
      INSTALL_INPUT.secret,
      expect.anything()
    );
    expect(cloudflare.calls()).toEqual([
      `GET ${CLOUDFLARE_API}${ACCOUNT}/tokens/verify`,
      `GET ${CLOUDFLARE_API}${ACCOUNT}/tokens/${TOKEN_ID}`,
    ]);
  });

  it("refuses an account id that isn't one, before it reads the secret", async () => {
    const cloudflare = cloudflareWith();

    await expect(
      validate({ ...INSTALL_INPUT, accountId: "ACME" })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(readToken).not.toHaveBeenCalled();
    expect(cloudflare.fetch).not.toHaveBeenCalled();
  });

  describe("the secret step", () => {
    it("names the step when the read fails, and doesn't call Cloudflare", async () => {
      vi.mocked(readToken).mockRejectedValue(
        new ConnectorError({
          message: "The connector isn't allowed to read the secret.",
          payload: { manager: "aws" },
          type: "insufficient_privileges",
        })
      );
      const cloudflare = cloudflareWith();

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        message: "The connector isn't allowed to read the secret.",
        payload: { manager: "aws", step: "secret" },
        type: "insufficient_privileges",
      });
      expect(cloudflare.fetch).not.toHaveBeenCalled();
    });
  });

  describe("the verify step", () => {
    it("fails when Cloudflare doesn't accept the token", async () => {
      const cloudflare = stubCloudflare({
        [`GET ${ACCOUNT}/tokens/verify`]: () =>
          failed(401, [{ code: 1000, message: "Invalid API Token" }]),
      });

      const { data } = await connectorError(validate);

      expect(data).toMatchObject({
        payload: { codes: "1000", status: 401, step: "verify" },
        type: "insufficient_privileges",
      });
      expect(cloudflare.fetch).toHaveBeenCalledOnce();
    });

    it.each(["disabled", "expired"])(
      "fails when the token is %s",
      async (status) => {
        cloudflareWith({ status });

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          message: `Cloudflare says the install token is ${status}, not active. Make a new install token, store it in the secret, and try again.`,
          payload: { status, step: "verify" },
          type: "insufficient_privileges",
        });
      }
    );
  });

  describe("the groups step", () => {
    it("fails when the token can't read itself", async () => {
      stubCloudflare({
        [`GET ${ACCOUNT}/tokens/verify`]: () =>
          ok({ id: TOKEN_ID, status: "active" }),
        [`GET ${ACCOUNT}/tokens/${TOKEN_ID}`]: () =>
          failed(403, [{ code: 9109, message: "Unauthorized" }]),
      });

      const { data } = await connectorError(validate);

      expect(data).toMatchObject({
        payload: { status: 403, step: "groups" },
        type: "insufficient_privileges",
      });
    });

    it("passes Zone Read on the whole account", async () => {
      cloudflareWith({ policies: [policy([TOKENS_WRITE, ZONE_READ])] });

      await expect(validate()).resolves.toMatchObject({ otherGroups: [] });
    });

    it.each([
      [
        "Account API Tokens Edit",
        [policy([ZONE_READ], ALL_ZONES)],
        [REQUIRED_GROUPS.accountApiTokensWrite],
      ],
      ["Zone Read", [policy([TOKENS_WRITE])], [REQUIRED_GROUPS.zoneRead]],
      [
        "both groups",
        [],
        [REQUIRED_GROUPS.accountApiTokensWrite, REQUIRED_GROUPS.zoneRead],
      ],
      [
        "Account API Tokens Edit on the account (it has it on all zones only)",
        [policy([TOKENS_WRITE, ZONE_READ], ALL_ZONES)],
        [REQUIRED_GROUPS.accountApiTokensWrite],
      ],
      [
        "the groups on this account (it has them on another)",
        [
          policy([TOKENS_WRITE, ZONE_READ], {
            "com.cloudflare.api.account.ffffffffffffffffffffffffffffffff": "*",
          }),
        ],
        [REQUIRED_GROUPS.accountApiTokensWrite, REQUIRED_GROUPS.zoneRead],
      ],
      [
        "Zone Read on all zones (it has it on one zone)",
        [
          policy([TOKENS_WRITE]),
          policy([ZONE_READ], {
            [ACCOUNT_KEY]: { "com.cloudflare.api.zone.abc": "*" },
          }),
        ],
        [REQUIRED_GROUPS.zoneRead],
      ],
      [
        "the groups as allowed (they are in a deny policy)",
        [policy([TOKENS_WRITE, ZONE_READ], { [ACCOUNT_KEY]: "*" }, "deny")],
        [REQUIRED_GROUPS.accountApiTokensWrite, REQUIRED_GROUPS.zoneRead],
      ],
    ])(
      "fails, naming them, when the token lacks %s",
      async (_case, policies, missing) => {
        cloudflareWith({ policies });

        const { data } = await connectorError(validate);

        const labels = missing.map(({ label }) => label).join(" and ");
        expect(data).toEqual({
          message: `The install token is missing ${labels}. Give the token ${missing.length === 1 ? "that group" : "those groups"} in the Cloudflare dashboard, then try again.`,
          payload: {
            missingGroups: missing.map(({ id }) => id).join(","),
            step: "groups",
          },
          type: "insufficient_privileges",
        });
      }
    );

    it("passes a token with other groups too, naming them sorted, and warns", async () => {
      const log = recordLogger();
      cloudflareWith({
        policies: [
          ...INSTALL_POLICIES,
          policy([{ id: "w", name: "Workers Scripts Write" }, { id: "dns" }]),
        ],
      });

      await expect(validate()).resolves.toStrictEqual({
        otherGroups: ["Workers Scripts Write", "dns"],
        tokenId: TOKEN_ID,
      });
      expect(log.lines()).toContainEqual([
        { otherGroups: ["Workers Scripts Write", "dns"] },
        "the install token holds groups beyond the two it needs",
      ]);
    });
  });

  it("shows nothing of the token or the pointer, however a check fails", async () => {
    for (const setup of [
      () => cloudflareWith({ policies: [] }),
      () => cloudflareWith({ status: "disabled" }),
      () =>
        stubCloudflare({
          [`GET ${ACCOUNT}/tokens/verify`]: () =>
            failed(401, [{ code: 1000, message: `bad ${TOKEN}` }]),
        }),
    ]) {
      const log = recordLogger();
      setup();

      const error = await connectorError(validate);

      const seen = log.seen(error, JSON.stringify(error.data));
      for (const marker of NEVER_SHOWN) {
        expect(seen).not.toContain(marker);
      }
      vi.mocked(logger.child).mockRestore();
    }
  });
});
