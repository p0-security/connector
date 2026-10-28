import { ConnectorError } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ADMIN_CREDENTIAL,
  AUTHORIZATION,
  HARBOR_HOST,
  ID_TOKEN,
  INSTANCE,
  NEVER_SHOWN,
  connectorError,
  logger,
  recordLogger,
} from "../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../allowlist.ts";
import {
  CLI_SECRET,
  type FakeHarborState,
  ORIGIN,
  fakeProject,
  newFakeHarbor,
} from "../../harbor/__tests__/fake-harbor.ts";
import { mintIdToken } from "../../harbor/oidc.ts";
import { connectorRouter } from "../../router.ts";
import { readAdminCredential } from "../../secrets.ts";

// The secret manager is `secrets.test.ts`'s business, and the identity
// provider `oidc.test.ts`'s. Here the read answers with the credential and the
// provider with the token, or fail, as each test says.
vi.mock("../../secrets.ts");
vi.mock("../../harbor/oidc.ts");

const API = `${ORIGIN}/api/v2.0`;
const PATTERN = "example\\.com";

/** A Harbor the admin account passes every check on, unless overridden. */
const harborWith = (overrides: Partial<FakeHarborState> = {}) =>
  newFakeHarbor({
    users: [
      { user_id: 3, username: "alice", email: "alice@example.com" },
      { user_id: 4, username: "bob", email: "bob@example.com" },
    ],
    projects: [fakeProject(1, "library", [], true), fakeProject(2, "team")],
    ...overrides,
  });

type Harbor = ReturnType<typeof harborWith>;

/**
 * Answers a call with `answer`'s response when it gives one, and as the
 * fake does otherwise.
 */
const intercept = (
  harbor: Harbor,
  answer: (method: string, url: string) => Response | undefined
) => {
  const fake = harbor.fetch.getMockImplementation();
  if (fake === undefined) throw new Error("the fake has no implementation");
  harbor.fetch.mockImplementation(
    async (url, init) => answer(init?.method ?? "GET", url) ?? fake(url, init)
  );
};

/** The token signs in as a user who isn't a system administrator. */
const NOT_ADMIN: Partial<FakeHarborState> = {
  users: [{ user_id: 99, username: "plain", email: "plain@example.com" }],
  caller: 99,
};

// Calling through the connector router also proves the `harbor` namespace is
// registered with its install router.
const validate = (input = INSTANCE) =>
  connectorRouter.createCaller({ logger }).harbor.install.validation.get(input);

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, PATTERN);
  vi.mocked(readAdminCredential).mockResolvedValue(ADMIN_CREDENTIAL);
  vi.mocked(mintIdToken).mockResolvedValue(ID_TOKEN);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("install validation", () => {
  it("reports Harbor's version and auth mode, and the connector's own pattern, after every check", async () => {
    const harbor = harborWith();

    await expect(validate()).resolves.toStrictEqual({
      harborVersion: "v2.14.0-44a74424",
      authMode: "oidc_auth",
      allowedEmailDomainPattern: PATTERN,
    });

    expect(readAdminCredential).toHaveBeenCalledWith(
      INSTANCE.secret,
      expect.anything()
    );
    expect(mintIdToken).toHaveBeenCalledTimes(1);
    expect(mintIdToken).toHaveBeenCalledWith(
      expect.objectContaining({
        credential: ADMIN_CREDENTIAL,
        host: HARBOR_HOST,
      })
    );
    // The checks, in order. An administrator holds every permission the
    // accesses use, so nothing more is probed.
    expect(harbor.calls()).toEqual([
      `GET ${API}/systeminfo`,
      `GET ${API}/users/current`,
    ]);
    for (const [, init] of harbor.fetch.mock.calls) {
      expect(new Headers(init?.headers).get("authorization")).toBe(
        AUTHORIZATION
      );
    }
  });

  // What the allowlist will compile is the value less the whitespace around
  // it, so that is what is reported.
  it("reports the pattern trimmed, and otherwise as it is set", async () => {
    vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, " (.+\\.)?Example\\.com \n");
    harborWith();

    await expect(validate()).resolves.toMatchObject({
      allowedEmailDomainPattern: "(.+\\.)?Example\\.com",
    });
  });

  // The parser hands the handler the instance's origin, whatever P0 sent.
  it("calls the instance's origin when the URL comes with a trailing slash", async () => {
    const harbor = harborWith();

    await validate({ ...INSTANCE, url: `https://${HARBOR_HOST}/` });

    expect(harbor.calls()[0]).toBe(`GET ${API}/systeminfo`);
  });

  it("refuses an instance that isn't https before it reads the secret", async () => {
    const harbor = harborWith();

    await expect(
      validate({ ...INSTANCE, url: `http://${HARBOR_HOST}` })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(readAdminCredential).not.toHaveBeenCalled();
    expect(harbor.fetch).not.toHaveBeenCalled();
  });

  describe("the secret step", () => {
    // The accesses read the secret too, so the read's own error names no step.
    it("names the step and the instance when the read fails, and doesn't call Harbor", async () => {
      vi.mocked(readAdminCredential).mockRejectedValue(
        new ConnectorError({
          type: "insufficient_privileges",
          message: "The connector isn't allowed to read the secret.",
          payload: { manager: "aws" },
        })
      );
      const harbor = harborWith();

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: "The connector isn't allowed to read the secret.",
        payload: { step: "secret", host: HARBOR_HOST, manager: "aws" },
      });
      expect(mintIdToken).not.toHaveBeenCalled();
      expect(harbor.fetch).not.toHaveBeenCalled();
    });
  });

  describe("the sign_in step", () => {
    // The accesses mint a token too, so the provider's own error names no step.
    it.each([
      ["the refresh token is refused", { reason: "admin_signin_expired" }],
      ["the provider can't be reached", {}],
    ])(
      "names the step and the instance when %s, and doesn't call Harbor",
      async (_what, payload) => {
        vi.mocked(mintIdToken).mockRejectedValue(
          new ConnectorError({
            type: "validation_error",
            message: "The provider refused.",
            payload: { ...payload, provider: "idp.example.com" },
          })
        );
        const harbor = harborWith();

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "validation_error",
          message: "The provider refused.",
          payload: {
            ...payload,
            provider: "idp.example.com",
            step: "sign_in",
            host: HARBOR_HOST,
          },
        });
        expect(harbor.fetch).not.toHaveBeenCalled();
      }
    );

    it("comes after the pattern step", async () => {
      vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, undefined);
      harborWith();

      const { data } = await connectorError(validate);

      expect(data.payload).toMatchObject({ step: "pattern" });
      expect(mintIdToken).not.toHaveBeenCalled();
    });
  });

  describe("the pattern step", () => {
    it.each<[what: string, pattern: string | undefined, problem: string]>([
      ["unset", undefined, "isn't set."],
      ["empty", "", "isn't set."],
      ["blank", "   ", "isn't set."],
      [
        "not a regex that compiles",
        "(example\\.com",
        "isn't a regular expression that compiles. The connector's log says why.",
      ],
      [
        "a regex only once it is wrapped",
        "example\\.com)|(.*",
        "isn't a regular expression that compiles. The connector's log says why.",
      ],
    ])(
      "fails, without calling Harbor, when the pattern is %s",
      async (_case, pattern, problem) => {
        vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, pattern);
        const harbor = harborWith();

        const { data } = await connectorError(validate);

        expect(data.type).toBe("validation_error");
        expect(data.payload).toEqual({ step: "pattern", host: HARBOR_HOST });
        expect(data.message).toBe(
          `The connector's ALLOWED_EMAIL_DOMAIN_PATTERN ${problem} Set it to a regular expression for the email domains that may receive access.`
        );
        expect(harbor.fetch).not.toHaveBeenCalled();
      }
    );

    // The message reaches the installer. The regex engine's message quotes
    // the pattern, so only the connector's log has it.
    it("logs the regex engine's error, and keeps it out of the message", async () => {
      vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "(example\\.com");
      const log = recordLogger();
      harborWith();

      const { data } = await connectorError(validate);

      expect(data.message).not.toContain("(example\\.com");
      expect(data.message).not.toContain("Unterminated group");
      expect(log.lines()).toContainEqual([
        {
          problem: {
            reason: "invalid_regex",
            detail:
              "Invalid regular expression: /(example\\.com/: Unterminated group",
          },
        },
        "the email domain allowlist is unusable; install validation fails",
      ]);
    });
  });

  describe("the systeminfo step", () => {
    // How each failure maps is errors.test.ts's business. Here, that a
    // failure of the system info call is reported at its step, and that
    // nothing else is tried.
    it("fails as unreachable when the connection is refused", async () => {
      const fetchMock = vi.fn(async () => {
        throw new TypeError("fetch failed", {
          cause: Object.assign(new Error("refused"), { code: "ECONNREFUSED" }),
        });
      });
      vi.stubGlobal("fetch", fetchMock);

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "upstream_unavailable",
        message: `The connector couldn't reach Harbor at ${HARBOR_HOST}: ECONNREFUSED. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { step: "systeminfo", host: HARBOR_HOST },
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    // Trying again won't help: the URL or the network has to change.
    it("says the host doesn't resolve, as the customer's to fix", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw new TypeError("fetch failed", {
            cause: Object.assign(new Error("lookup"), { code: "ENOTFOUND" }),
          });
        })
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `${HARBOR_HOST} doesn't resolve from the connector. Check the instance's URL, and that the connector's network can resolve its host.`,
        payload: { step: "systeminfo", host: HARBOR_HOST, code: "ENOTFOUND" },
      });
    });

    it("says Harbor may be down when it answers 503", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => Response.json({}, { status: 503 }))
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "upstream_unavailable",
        message: `${HARBOR_HOST} answered GET /api/v2.0/systeminfo with 503. Check that Harbor is running, and try again.`,
        payload: { step: "systeminfo", host: HARBOR_HOST, status: 503 },
      });
    });

    // The URL is whatever P0 sent: a body of any length is read only to the
    // cap (api.test.ts), so a padded one that fits is still Harbor's.
    it("reads a system info answer that is mostly padding, up to the cap", async () => {
      const harbor = harborWith();
      intercept(harbor, (_method, url) =>
        url.endsWith("/systeminfo")
          ? new Response(
              `${" ".repeat(1000 * 1024)}${JSON.stringify({
                auth_mode: "oidc_auth",
                harbor_version: "v2.14.0-44a74424",
              })}`
            )
          : undefined
      );

      await expect(validate()).resolves.toMatchObject({
        authMode: "oidc_auth",
      });
    });

    // Harbor answers this route for anyone, so a refusal isn't Harbor's.
    it.each([401, 403])(
      "blames what is in front of Harbor when the call is refused with %i",
      async (status) => {
        vi.stubGlobal(
          "fetch",
          vi.fn(async () => Response.json({}, { status }))
        );

        const { data } = await connectorError(validate);

        expect(data.type).toBe("insufficient_privileges");
        expect(data.payload).toEqual({
          step: "systeminfo",
          host: HARBOR_HOST,
          status,
        });
        expect(data.message).toBe(
          `Something in front of Harbor at ${HARBOR_HOST} refused the connector's call with ${status}: Harbor itself answers GET /api/v2.0/systeminfo for anyone. Let the connector through the proxy or gateway in front of the instance.`
        );
      }
    );

    it.each<[what: string, answer: () => Response, status: number | undefined]>(
      [
        ["a redirect", () => new Response(null, { status: 307 }), 307],
        ["a 404", () => Response.json({}, { status: 404 }), 404],
        ["a page", () => new Response("<!doctype html>"), undefined],
        [
          "JSON without an auth mode",
          () => Response.json({ up: true }),
          undefined,
        ],
      ]
    )("fails as not Harbor on %s", async (_case, answer, status) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => answer())
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `${HARBOR_HOST} didn't answer GET /api/v2.0/systeminfo the way Harbor does${status === undefined ? "" : `: it answered ${status}`}. Check that the instance's URL points at Harbor.`,
        payload: {
          step: "systeminfo",
          host: HARBOR_HOST,
          ...(status === undefined ? {} : { status }),
        },
      });
    });

    describe("the version", () => {
      // Up to 2.12.4 Harbor tells anyone its version, so an old Harbor fails
      // for its version, before the token is tried.
      it.each<[version: string, parsed: string]>([
        ["v2.11.2-12345678", "2.11.2"],
        ["v2.9.0-abcdef12", "2.9.0"],
        ["v1.10.18", "1.10.18"],
      ])(
        "refuses Harbor %s before it tries the token",
        async (version, parsed) => {
          const harbor = harborWith({ version });

          const { data } = await connectorError(validate);

          expect(data).toEqual({
            type: "validation_error",
            message: `Harbor at ${HARBOR_HOST} is version ${parsed}. The connector needs Harbor 2.12.0 or later.`,
            payload: {
              step: "systeminfo",
              host: HARBOR_HOST,
              harborVersion: parsed,
            },
          });
          expect(harbor.calls()).toEqual([`GET ${API}/systeminfo`]);
        }
      );

      it.each(["v2.12.0-9da38ae0", "v2.12.4-0", "v2.13.0-1", "v3.0.0"])(
        "accepts Harbor %s",
        async (version) => {
          harborWith({ version });

          await expect(validate()).resolves.toMatchObject({
            harborVersion: version,
          });
        }
      );

      it("refuses a version it can't read, without quoting it", async () => {
        harborWith({ version: "latest <script>" });

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "validation_error",
          message: `Harbor at ${HARBOR_HOST} reports a version the connector can't read. It needs Harbor 2.12.0 or later.`,
          payload: { step: "systeminfo", host: HARBOR_HOST },
        });
      });

      // Harbor tells every caller it authenticated its version.
      it("fails when Harbor accepts the token but reports no version", async () => {
        const harbor = harborWith();
        intercept(harbor, (_method, url) =>
          url.endsWith("/systeminfo")
            ? Response.json({ auth_mode: "oidc_auth" })
            : undefined
        );

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "validation_error",
          message: `Harbor at ${HARBOR_HOST} accepted the admin account's ID token but didn't report its version, which every Harbor the connector supports does. Check that the instance's URL points at Harbor itself, not at a proxy that changes its answers.`,
          payload: { step: "systeminfo", host: HARBOR_HOST },
        });
      });
    });

    describe("the auth mode", () => {
      // Harbor accepts an ID token only in OIDC mode, and LDAP mode is no
      // longer supported.
      it.each(["ldap_auth", "db_auth", "uaa_auth", "http_auth"])(
        "refuses %s, naming the one it supports, before it tries the token",
        async (authMode) => {
          const harbor = harborWith({ authMode });

          const { data } = await connectorError(validate);

          expect(data).toEqual({
            type: "validation_error",
            message: `Harbor at ${HARBOR_HOST} signs users in with ${authMode}. The connector signs in to Harbor with an OIDC ID token, so it supports oidc_auth only.`,
            payload: { step: "systeminfo", host: HARBOR_HOST, authMode },
          });
          expect(harbor.calls()).toEqual([`GET ${API}/systeminfo`]);
        }
      );

      // Whatever answered chose the text, so it isn't repeated.
      it("refuses a mode it doesn't know, without quoting it", async () => {
        harborWith({ authMode: "<b>saml</b>" });

        const { data } = await connectorError(validate);

        expect(data.message).toBe(
          `Harbor at ${HARBOR_HOST} signs users in with an auth mode the connector doesn't know. The connector signs in to Harbor with an OIDC ID token, so it supports oidc_auth only.`
        );
        expect(data.payload).toEqual({ step: "systeminfo", host: HARBOR_HOST });
      });
    });
  });

  describe("the authenticate step", () => {
    // Harbor doesn't answer a token it doesn't accept with a 401 on the
    // system info. It answers as it would an anonymous caller.
    // `GET /users/current` refuses one.
    it("fails with admin_token_rejected when Harbor doesn't accept the token", async () => {
      harborWith({ token: "another.token.x" });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `Harbor at ${HARBOR_HOST} didn't accept the ID token the connector minted for its admin account. Check that the admin credential's clientId is Harbor's OIDC client ID, that the admin account has signed in to Harbor once, and that Harbor signs users in with OIDC.`,
        payload: {
          reason: "admin_token_rejected",
          step: "authenticate",
          host: HARBOR_HOST,
          status: 401,
        },
      });
    });

    // Up to 2.12.4 Harbor tells anyone its version, so the floor passes
    // before the token is tried, and the token still fails.
    it("fails for the token on a Harbor that tells anyone its version", async () => {
      harborWith({ token: "another.token.x", version: "v2.12.0-9da38ae0" });

      const { data } = await connectorError(validate);

      expect(data.payload).toMatchObject({
        reason: "admin_token_rejected",
        step: "authenticate",
      });
    });

    it("fails with admin_not_harbor_admin when the token's user doesn't have the flag", async () => {
      harborWith(NOT_ADMIN);

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `The admin account the connector signs in to Harbor at ${HARBOR_HOST} with isn't a Harbor system administrator. Make it one on Harbor's Users page.`,
        payload: {
          reason: "admin_not_harbor_admin",
          step: "authenticate",
          host: HARBOR_HOST,
        },
      });
    });

    it.each<[status: number, type: string]>([
      [503, "upstream_unavailable"],
      [429, "rate_limited"],
      [404, "validation_error"],
    ])(
      "fails at the step when GET /users/current answers %i",
      async (status, type) => {
        const harbor = harborWith();
        intercept(harbor, (_method, url) =>
          url.endsWith("/users/current")
            ? Response.json({}, { status })
            : undefined
        );

        const { data } = await connectorError(validate);

        expect(data.type).toBe(type);
        expect(data.payload).toMatchObject({ step: "authenticate", status });
      }
    );

    it("fails at the step, rather than read as an administrator, when the answer has no flag", async () => {
      const harbor = harborWith();
      intercept(harbor, (_method, url) =>
        url.endsWith("/users/current")
          ? Response.json({ user_id: 9000, username: "harbor-automation" })
          : undefined
      );

      const { data } = await connectorError(validate);

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ step: "authenticate", host: HARBOR_HOST });
    });
  });

  describe("the credential and the pointer", () => {
    const OUTCOMES: [what: string, state: Partial<FakeHarborState>][] = [
      ["every check passes", {}],
      ["the account isn't an administrator", NOT_ADMIN],
      ["Harbor doesn't accept the token", { token: "another.token.x" }],
      ["Harbor is too old", { version: "v2.11.0" }],
      ["Harbor is in LDAP mode", { authMode: "ldap_auth" }],
    ];

    it("reach none of them when Harbor rejects the token", async () => {
      // The sentinel token is what the connector sends: the fake is told to
      // accept nothing, by a 401 on everything but the system info.
      const log = recordLogger();
      const harbor = harborWith();
      intercept(harbor, (_method, url) =>
        url.endsWith("/systeminfo")
          ? undefined
          : Response.json({}, { status: 401 })
      );

      const outcome = await validate().catch((error: unknown) => error);

      const seen = log.seen(outcome);
      for (const marker of [...NEVER_SHOWN, AUTHORIZATION]) {
        expect(seen).not.toContain(marker);
      }
    });

    it.each<[what: string, answer: () => Response]>([
      ["Harbor answers 503", () => Response.json({}, { status: 503 })],
      ["the answer isn't Harbor's", () => new Response("<html>")],
    ])("reach none of them when %s", async (_what, answer) => {
      const log = recordLogger();
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => answer())
      );

      const outcome = await validate().catch((error: unknown) => error);

      const seen = log.seen(outcome);
      for (const marker of [...NEVER_SHOWN, AUTHORIZATION]) {
        expect(seen).not.toContain(marker);
      }
    });

    it("reach none of them when the pattern is unset", async () => {
      vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, undefined);
      const log = recordLogger();
      harborWith();

      const outcome = await validate().catch((error: unknown) => error);

      const seen = log.seen(outcome);
      for (const marker of NEVER_SHOWN) expect(seen).not.toContain(marker);
    });

    it.each(OUTCOMES)(
      "reach no log line, no logger's bindings and no error when %s",
      async (_case, state) => {
        const log = recordLogger();
        harborWith(state);

        const outcome = await validate().catch((error: unknown) => error);

        expect(log.lines()).not.toHaveLength(0);
        const seen = log.seen(outcome);
        for (const marker of [...NEVER_SHOWN, AUTHORIZATION, CLI_SECRET]) {
          expect(seen).not.toContain(marker);
        }
      }
    );

    it("reach none of them when a call fails, quoting the request", async () => {
      const log = recordLogger();
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw new TypeError(`fetch failed (${AUTHORIZATION})`, {
            cause: new Error(`socket hang up (${ID_TOKEN})`),
          });
        })
      );

      const outcome = await validate().catch((error: unknown) => error);

      const seen = log.seen(outcome);
      for (const marker of [...NEVER_SHOWN, AUTHORIZATION]) {
        expect(seen).not.toContain(marker);
      }
    });
  });
});
