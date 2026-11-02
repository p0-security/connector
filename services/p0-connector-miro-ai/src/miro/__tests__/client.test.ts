import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  API,
  TEAM_ID,
  TOKEN,
  USER_ID,
  connectorError,
  logger,
} from "../../__tests__/fixtures.ts";
import {
  MAX_ATTEMPTS,
  MAX_BOARD_PAGES,
  MAX_RETRY_WAIT_SECONDS,
  MiroError,
  type Pause,
  miroId,
  newMiroApi,
  newMiroClient,
  parseJson,
} from "../client.ts";
import { toConnectorError } from "../errors.ts";
import { ALL_SCOPES, boards, errorAnswer, newFakeMiro } from "./fake-miro.ts";

const pause = vi.fn<Pause>(async () => {});

const api = () => newMiroApi({ logger, pause, token: TOKEN });
const client = () => newMiroClient(api());

/** The {@link MiroError} `run` fails with. Anything else fails the test. */
const miroError = async (run: () => Promise<unknown>) => {
  const outcome = await run().then(
    () => new Error("expected the call to throw"),
    (error: unknown) => error
  );
  if (outcome instanceof MiroError) return outcome;
  throw outcome;
};

const tooManyRequests = (retryAfter?: string) =>
  new Response(null, {
    status: 429,
    headers: retryAfter === undefined ? {} : { "retry-after": retryAfter },
  });

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("parseJson", () => {
  // `JSON.parse` alone reads 3458764688747789111 as 3458764688747789000.
  it("keeps an integer above 2^53 as its digits", () => {
    expect(parseJson(`{"id":${USER_ID},"n":3}`)).toEqual({ id: USER_ID, n: 3 });
  });

  it("leaves strings that look like large numbers alone", () => {
    expect(parseJson(`{"id":"${USER_ID}"}`)).toEqual({ id: USER_ID });
  });

  it("answers undefined for text that isn't JSON", () => {
    expect(parseJson("<html>")).toBeUndefined();
  });
});

describe("miroId", () => {
  it.each([
    ["a string", USER_ID, USER_ID],
    ["a safe number", 42, "42"],
  ])("reads %s as a string", (_case, value, id) => {
    expect(miroId.parse(value)).toBe(id);
  });

  // Only a runtime without the reviver's source text would send one.
  it("refuses a number that may have been rounded", () => {
    expect(miroId.safeParse(2 ** 60).success).toBe(false);
  });
});

describe("the Miro API", () => {
  it("sends the token as a bearer token, to api.miro.com, without following redirects", async () => {
    const miro = newFakeMiro();

    await client().fetchTokenInfo();

    const [url, init] = miro.fetch.mock.calls[0] ?? [];
    expect(url).toBe(`${API}/v1/oauth-token`);
    expect(new Headers(init?.headers).get("authorization")).toBe(
      `Bearer ${TOKEN}`
    );
    expect(init?.redirect).toBe("manual");
  });

  it("refuses a route outside its allowlist before calling Miro", async () => {
    const miro = newFakeMiro();

    const { data } = await connectorError(() =>
      // @ts-expect-error -- not a route the connector makes.
      api().read({ route: "postBoardMembers", answer: z.unknown() })
    );

    expect(data.type).toBe("validation_error");
    expect(miro.fetch).not.toHaveBeenCalled();
  });

  describe("on a 429", () => {
    it("waits Retry-After and tries again", async () => {
      const miro = newFakeMiro();
      let limited = 1;
      miro.intercept(() => (limited-- > 0 ? tooManyRequests("1") : undefined));

      await expect(client().fetchTokenInfo()).resolves.toMatchObject({
        teamId: TEAM_ID,
      });
      expect(pause.mock.calls).toEqual([[1]]);
      expect(miro.fetch).toHaveBeenCalledTimes(2);
    });

    it("waits no longer than its cap, however long Retry-After asks", async () => {
      const miro = newFakeMiro();
      let limited = 1;
      miro.intercept(() =>
        limited-- > 0 ? tooManyRequests("600") : undefined
      );

      await client().fetchTokenInfo();

      expect(pause.mock.calls).toEqual([[MAX_RETRY_WAIT_SECONDS]]);
    });

    it("backs off when Retry-After says nothing", async () => {
      const miro = newFakeMiro();
      miro.intercept(() => tooManyRequests());

      await miroError(() => client().fetchTokenInfo());

      expect(pause.mock.calls).toEqual([[1], [2]]);
    });

    it(`gives up after ${MAX_ATTEMPTS} tries, as rate_limited with Retry-After`, async () => {
      const miro = newFakeMiro();
      miro.intercept(() => tooManyRequests("30"));

      const error = await miroError(() => client().fetchTokenInfo());

      expect(miro.fetch).toHaveBeenCalledTimes(MAX_ATTEMPTS);
      expect(toConnectorError(error)).toMatchObject({
        data: {
          type: "rate_limited",
          payload: { status: 429, retryAfter: 30 },
        },
      });
    });

    it("tries nothing else again", async () => {
      const miro = newFakeMiro();
      miro.intercept(() => errorAnswer(503, "Unavailable"));

      await miroError(() => client().fetchTokenInfo());

      expect(miro.fetch).toHaveBeenCalledTimes(1);
      expect(pause).not.toHaveBeenCalled();
    });
  });

  it("refuses an answer larger than its cap", async () => {
    const miro = newFakeMiro();
    miro.intercept(() => new Response("x".repeat(3 * 1024 * 1024)));

    const { failure } = await miroError(() => client().fetchTokenInfo());

    expect(failure).toEqual({ kind: "unexpected", reason: "too_large" });
  });
});

describe("the Miro client", () => {
  it("reports the token's team, user and scopes", async () => {
    newFakeMiro();

    await expect(client().fetchTokenInfo()).resolves.toEqual({
      scopes: ALL_SCOPES,
      teamId: TEAM_ID,
      userId: USER_ID,
    });
  });

  it("reads ids sent as numbers exactly", async () => {
    newFakeMiro({ numericIds: true });

    await expect(client().fetchTokenInfo()).resolves.toMatchObject({
      teamId: TEAM_ID,
      userId: USER_ID,
    });
  });

  it("stops paging boards once it has read them all", async () => {
    const miro = newFakeMiro({ boards: boards(50, "owner") });

    await expect(client().countShareableBoards(TEAM_ID)).resolves.toBe(50);
    expect(miro.fetch).toHaveBeenCalledTimes(1);
  });

  it(`gives up on a listing that runs past ${MAX_BOARD_PAGES} pages`, async () => {
    const miro = newFakeMiro();
    miro.intercept((url) =>
      url.includes("/v2/boards")
        ? Response.json({
            data: [{ id: "b", currentUserMembership: { role: "owner" } }],
            total: 1_000_000,
          })
        : undefined
    );

    const { failure } = await miroError(() =>
      client().countShareableBoards(TEAM_ID)
    );

    expect(failure).toEqual({ kind: "unexpected", reason: "endless" });
    expect(miro.fetch).toHaveBeenCalledTimes(MAX_BOARD_PAGES);
  });
});
