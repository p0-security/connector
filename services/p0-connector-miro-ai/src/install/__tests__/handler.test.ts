import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it, vi } from "vitest";

import {
  API,
  INSTALL_INPUT,
  NEVER_SHOWN,
  TEAM_ID,
  TOKEN,
  connectorError,
  logger,
  recordLogger,
  stubToken,
} from "../../__tests__/fixtures.ts";
import {
  type FakeMiroState,
  boards,
  errorAnswer,
  newFakeMiro,
} from "../../miro/__tests__/fake-miro.ts";
import { connectorRouter } from "../../router.ts";
import { readToken } from "../../secrets.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token, or fails, as each test says.
vi.mock("../../secrets.ts");

/** A team the token passes every check on, with one shareable board, unless overridden. */
const miroWith = (overrides: FakeMiroState = {}) =>
  newFakeMiro({ boards: boards(1, "coowner"), ...overrides });

// Calling through the connector router also proves the `miro-ai` namespace
// is registered with its install router.
const validate = (input: unknown = INSTALL_INPUT) => {
  const { install } = connectorRouter.createCaller({ logger })["miro-ai"];
  // @ts-expect-error -- some tests send input that doesn't parse, on purpose.
  return install.validation.get(input);
};

const BOARDS_PAGE = `GET ${API}/v2/boards?limit=50&offset=0&team_id=${TEAM_ID}`;

stubToken();

describe("install validation", () => {
  it("reports the team and its shareable boards after every check", async () => {
    const miro = miroWith();

    await expect(validate()).resolves.toStrictEqual({
      teamId: TEAM_ID,
      shareableBoards: 1,
    });

    expect(readToken).toHaveBeenCalledWith(
      INSTALL_INPUT.secret,
      expect.anything()
    );
    // Every check only reads.
    expect(miro.calls()).toEqual([`GET ${API}/v1/oauth-token`, BOARDS_PAGE]);
  });

  // An id above 2^53 sent as a JSON number would round to another team's.
  it("reads a team id Miro sends as a number exactly", async () => {
    miroWith({ numericIds: true });

    await expect(validate()).resolves.toMatchObject({ teamId: TEAM_ID });
  });

  it("refuses a secret pointer that doesn't parse, before it reads the secret", async () => {
    const miro = miroWith();

    await expect(
      validate({ secret: { manager: "gcp", projectId: "x", secretId: "s" } })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(readToken).not.toHaveBeenCalled();
    expect(miro.fetch).not.toHaveBeenCalled();
  });

  describe("the secret step", () => {
    it("names the step when the read fails, and doesn't call Miro", async () => {
      vi.mocked(readToken).mockRejectedValue(
        new ConnectorError({
          type: "insufficient_privileges",
          message: "The connector isn't allowed to read the secret.",
          payload: { manager: "aws" },
        })
      );
      const miro = miroWith();

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: "The connector isn't allowed to read the secret.",
        payload: { step: "secret", manager: "aws" },
      });
      expect(miro.fetch).not.toHaveBeenCalled();
    });
  });

  describe("the authenticate step", () => {
    it("fails as insufficient_privileges when Miro doesn't accept the token", async () => {
      const miro = miroWith({ token: "another-token" });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message:
          "Miro didn't accept the connector's access token on GET /v1/oauth-token (401). Check that the token in the secret is current: Miro revokes it when the connector user uninstalls the app.",
        payload: { step: "authenticate", status: 401 },
      });
      expect(miro.calls()).toEqual([`GET ${API}/v1/oauth-token`]);
    });

    // A token keeps the scopes it was issued with (spec V1).
    it("fails, naming the scope, when the token lacks team:read", async () => {
      const miro = miroWith({ scopes: ["boards:read", "boards:write"] });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message:
          "The connector user's Miro access token is missing the scope team:read. Add the scope to the app, then reinstall it and store the new token.",
        payload: { step: "authenticate", missingScopes: "team:read" },
      });
      expect(miro.calls()).toEqual([`GET ${API}/v1/oauth-token`]);
    });

    it("names every missing scope", async () => {
      miroWith({ scopes: ["boards:read"] });

      const { data } = await connectorError(validate);

      expect(data.message).toBe(
        "The connector user's Miro access token is missing the scopes boards:write, team:read. Add them to the app, then reinstall it and store the new token."
      );
      expect(data.payload).toMatchObject({
        missingScopes: "boards:write, team:read",
      });
    });

    it("fails on an answer without a team", async () => {
      const miro = miroWith();
      miro.intercept((url) =>
        url.endsWith("/v1/oauth-token")
          ? Response.json({ scopes: [], user: { id: "1" } })
          : undefined
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "unknown",
        message:
          "Miro answered GET /v1/oauth-token with something the connector can't read (wrong_shape). Try again, and contact P0 support if it keeps happening.",
        payload: { step: "authenticate", reason: "wrong_shape" },
      });
    });

    // A redirect could take the token to another host, so the connector
    // never follows one.
    it("fails on a redirect, with no second call", async () => {
      const miro = miroWith();
      miro.intercept(
        () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://evil.example/v1/oauth-token" },
          })
      );

      const { data } = await connectorError(validate);

      expect(data).toMatchObject({
        type: "validation_error",
        payload: { step: "authenticate", status: 302 },
      });
      expect(miro.fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe("the boards step", () => {
    it("counts only boards the connector user owns or co-owns, across pages", async () => {
      const miro = miroWith({
        boards: [
          ...boards(30, "owner"),
          ...boards(30, "editor"),
          ...boards(10, null),
          ...boards(25, "coowner"),
        ],
      });

      await expect(validate()).resolves.toStrictEqual({
        teamId: TEAM_ID,
        shareableBoards: 55,
      });
      expect(miro.calls()).toEqual([
        `GET ${API}/v1/oauth-token`,
        BOARDS_PAGE,
        `GET ${API}/v2/boards?limit=50&offset=50&team_id=${TEAM_ID}`,
      ]);
    });

    // Nothing can be requested yet, but the install works: P0 warns.
    it("passes with zero shareable boards, and logs a warning", async () => {
      const log = recordLogger();
      miroWith({ boards: [...boards(2, "editor"), ...boards(1, null)] });

      await expect(validate()).resolves.toStrictEqual({
        teamId: TEAM_ID,
        shareableBoards: 0,
      });
      expect(log.lines()).toContainEqual([
        { teamId: TEAM_ID },
        "the connector user owns or co-owns no board in the team, so none can be requested",
      ]);
    });

    it("names the step when Miro refuses the listing", async () => {
      const miro = miroWith();
      miro.intercept((url) =>
        url.includes("/v2/boards") ? errorAnswer(403, "Forbidden") : undefined
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message:
          "Miro refused GET /v2/boards with 403: the access token's scopes, or the connector user's role, don't allow it.",
        payload: { step: "boards", status: 403 },
      });
    });
  });

  // Whichever way validation ends, the token and the secret's pointer stay
  // out of the answer, the error and every log line.
  it.each<[string, () => void]>([
    ["it passes", () => miroWith()],
    ["the token is refused", () => miroWith({ token: "other" })],
    [
      "Miro echoes the token in its error",
      () => {
        const miro = miroWith();
        miro.intercept(() => errorAnswer(400, `bad token ${TOKEN}`));
      },
    ],
    [
      "the connection fails, quoting the request",
      () =>
        vi.stubGlobal(
          "fetch",
          vi.fn(async () => {
            throw new TypeError(`fetch failed ${TOKEN}`, {
              cause: new Error(`socket hang up Authorization: Bearer ${TOKEN}`),
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
