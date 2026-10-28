import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT_ID,
  API,
  INSTALL_INPUT,
  LAUNCHDARKLY_HOST,
  NEVER_SHOWN,
  PATTERN,
  TOKEN,
  TOKEN_OWNER_ID,
  connectorError,
  logger,
  recordLogger,
  stubPatternAndToken,
} from "../../__tests__/fixtures.ts";
import { DOMAIN_ALLOW_PATTERN_ENV } from "../../allowlist.ts";
import {
  type FakeLaunchDarklyState,
  PERSONAL_CALLER,
  errorAnswer,
  newFakeLaunchDarkly,
} from "../../launchdarkly/__tests__/fake-launchdarkly.ts";
import { connectorRouter } from "../../router.ts";
import { readToken } from "../../secrets.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token, or fails, as each test says.
vi.mock("../../secrets.ts");

/** An account the token passes every check on, unless overridden. */
const launchDarklyWith = (overrides: FakeLaunchDarklyState = {}) =>
  newFakeLaunchDarkly(overrides);

type LaunchDarkly = ReturnType<typeof launchDarklyWith>;

/**
 * Answers a call with `answer`'s response when it gives one, and as the
 * fake does otherwise.
 */
const intercept = (
  launchDarkly: LaunchDarkly,
  answer: (url: string) => Response | undefined
) => {
  const fake = launchDarkly.fetch.getMockImplementation();
  if (fake === undefined) throw new Error("the fake has no implementation");
  launchDarkly.fetch.mockImplementation(
    async (url, init) => answer(url) ?? fake(url, init)
  );
};

// Calling through the connector router also proves the `launchdarkly`
// namespace is registered with its install router.
const validate = (input: unknown = INSTALL_INPUT) =>
  connectorRouter
    .createCaller({ logger })
    // @ts-expect-error -- some tests send input that doesn't parse, on purpose.
    .launchdarkly.install.validation.get(input);

stubPatternAndToken();

describe("install validation", () => {
  it("reports the account, the token and the pattern after every check", async () => {
    const launchDarkly = launchDarklyWith();

    await expect(validate()).resolves.toStrictEqual({
      accountId: ACCOUNT_ID,
      tokenKind: "service",
      tokenOwnerMemberId: null,
      domainPattern: PATTERN,
    });

    expect(readToken).toHaveBeenCalledWith(
      INSTALL_INPUT.secret,
      expect.anything()
    );
    // Nothing Enterprise-only is asked for.
    expect(launchDarkly.calls()).toEqual([`GET ${API}/caller-identity`]);
  });

  it("reports the member a personal token acts as", async () => {
    launchDarklyWith({ caller: PERSONAL_CALLER });

    await expect(validate()).resolves.toStrictEqual({
      accountId: ACCOUNT_ID,
      tokenKind: "personal",
      tokenOwnerMemberId: TOKEN_OWNER_ID,
      domainPattern: PATTERN,
    });
  });

  // P0 names an instance, never a URL, so there is no host to send the
  // token to but the three.
  it("refuses an instance outside the three before it reads the secret", async () => {
    const launchDarkly = launchDarklyWith();

    await expect(
      validate({ ...INSTALL_INPUT, instance: "launchdarkly.evil.example" })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(readToken).not.toHaveBeenCalled();
    expect(launchDarkly.fetch).not.toHaveBeenCalled();
  });

  describe("the secret step", () => {
    // The accesses read the secret too, so the read's own error names no step.
    it("names the step and the host when the read fails, and doesn't call LaunchDarkly", async () => {
      vi.mocked(readToken).mockRejectedValue(
        new ConnectorError({
          type: "insufficient_privileges",
          message: "The connector isn't allowed to read the secret.",
          payload: { manager: "aws" },
        })
      );
      const launchDarkly = launchDarklyWith();

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: "The connector isn't allowed to read the secret.",
        payload: { step: "secret", host: LAUNCHDARKLY_HOST, manager: "aws" },
      });
      expect(launchDarkly.fetch).not.toHaveBeenCalled();
    });
  });

  describe("the authenticate step", () => {
    it("fails as insufficient_privileges when LaunchDarkly doesn't accept the token", async () => {
      const launchDarkly = launchDarklyWith({ token: "api-another-token" });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: `LaunchDarkly at ${LAUNCHDARKLY_HOST} didn't accept the connector's access token on GET /api/v2/caller-identity (401). Check that the token in the secret is current and belongs to this account: a reset or expired token is refused.`,
        payload: { step: "authenticate", host: LAUNCHDARKLY_HOST, status: 401 },
      });
      expect(launchDarkly.calls()).toEqual([`GET ${API}/caller-identity`]);
    });

    // A personal token acts as a member, which the connector must know to
    // leave alone.
    it("fails on a personal token whose identity names no member", async () => {
      const launchDarkly = launchDarklyWith();
      intercept(launchDarkly, (url) =>
        url.endsWith("/caller-identity")
          ? Response.json({ accountId: ACCOUNT_ID, serviceToken: false })
          : undefined
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "unknown",
        message: `LaunchDarkly at ${LAUNCHDARKLY_HOST} answered GET /api/v2/caller-identity with something the connector can't read (wrong_shape). Try again, and contact P0 support if it keeps happening.`,
        payload: {
          step: "authenticate",
          host: LAUNCHDARKLY_HOST,
          reason: "wrong_shape",
        },
      });
    });

    // A redirect could take the token to another host, so the connector
    // never follows one.
    it("fails on a redirect, with no second call", async () => {
      const launchDarkly = launchDarklyWith();
      intercept(
        launchDarkly,
        () =>
          new Response(null, {
            status: 302,
            headers: {
              location: "https://evil.example/api/v2/caller-identity",
            },
          })
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `LaunchDarkly at ${LAUNCHDARKLY_HOST} answered GET /api/v2/caller-identity with a redirect (302), which the connector doesn't follow. Contact P0 support if it keeps happening.`,
        payload: { step: "authenticate", host: LAUNCHDARKLY_HOST, status: 302 },
      });
      expect(launchDarkly.fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe("the domains step", () => {
    it.each<[what: string, pattern: string | undefined, problem: string]>([
      ["unset", undefined, "isn't set."],
      [
        "not a regex that compiles",
        "(example\\.com",
        "isn't a regular expression that compiles. The connector's log says why.",
      ],
    ])(
      "fails, after the other checks, when the pattern is %s",
      async (_case, pattern, problem) => {
        vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, pattern);
        const launchDarkly = launchDarklyWith();

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "validation_error",
          message: `The connector's DOMAIN_ALLOW_PATTERN ${problem} Set it to a regular expression for the email domains that may receive access.`,
          payload: { step: "domains", host: LAUNCHDARKLY_HOST },
        });
        expect(launchDarkly.fetch).toHaveBeenCalledTimes(1);
      }
    );
  });

  // Whichever way validation ends, the token and the secret's pointer stay
  // out of the answer, the error and every log line.
  it.each<[string, () => void]>([
    ["it passes", () => launchDarklyWith()],
    ["the token is refused", () => launchDarklyWith({ token: "other" })],
    [
      "LaunchDarkly echoes the token in its error",
      () => {
        const launchDarkly = launchDarklyWith();
        intercept(launchDarkly, () =>
          errorAnswer(400, {
            code: "invalid_request",
            message: `bad token ${TOKEN}`,
          })
        );
      },
    ],
    [
      "the connection fails, quoting the request",
      () =>
        vi.stubGlobal(
          "fetch",
          vi.fn(async () => {
            throw new TypeError(`fetch failed ${TOKEN}`, {
              cause: new Error(`socket hang up Authorization: ${TOKEN}`),
            });
          })
        ),
    ],
  ])("shows no token or pointer when %s", async (_case, arrange) => {
    const log = recordLogger();
    arrange();

    const outcome = await validate().catch((error: unknown) => error);

    const seen = log.seen(
      outcome,
      outcome instanceof ConnectorError ? outcome.data : undefined
    );
    for (const marker of NEVER_SHOWN) {
      expect(seen).not.toContain(marker);
    }
  });
});
