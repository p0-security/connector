import { ConnectorError } from "@p0security/connector";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  API,
  EMAIL,
  MEMBER_ID,
  NEVER_SHOWN,
  TOKEN,
  launchDarklyError,
  logger,
  recordLogger,
} from "../../__tests__/fixtures.ts";
import type { Instance } from "../../account.ts";
import { MAX_ANSWER_BYTES, newLaunchDarklyApi, segment } from "../api.ts";

const ITEMS = z.object({ items: z.array(z.unknown()) });

type Fetch = (url: string, init: RequestInit) => Promise<Response>;

const stubFetch = (answer: Fetch) => {
  const mock = vi.fn(answer);
  vi.stubGlobal("fetch", mock);
  return mock;
};

const api = (instance: Instance = "commercial") =>
  newLaunchDarklyApi({ instance, token: TOKEN, logger });

/** The {@link ConnectorError} `run` fails with, before any call is made. */
const refusedBeforeFetch = async (run: () => Promise<unknown>) => {
  const fetchMock = stubFetch(async () => Response.json({}));
  const outcome = await run().then(
    () => new Error("expected the call to be refused"),
    (error: unknown) => error
  );
  expect(fetchMock).not.toHaveBeenCalled();
  if (outcome instanceof ConnectorError) return outcome;
  throw outcome;
};

/** The JSON a call sent. */
const sentJson = (init?: RequestInit): unknown => {
  if (typeof init?.body !== "string") throw new Error("no JSON body");
  return JSON.parse(init.body);
};

/** A body of `chunks` 16 KiB chunks, which counts the chunks it was asked for. */
const streamed = (chunks: number) => {
  const stream = { pulled: 0, cancelled: false };
  const body = new ReadableStream<Uint8Array>(
    {
      pull: (controller) => {
        if (stream.pulled === chunks) return controller.close();
        stream.pulled += 1;
        controller.enqueue(new Uint8Array(16 * 1024).fill(0x20));
      },
      cancel: () => {
        stream.cancelled = true;
      },
    },
    // No read-ahead, so `pulled` is what the connector asked for.
    { highWaterMark: 0 }
  );
  return { stream, body };
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("segment", () => {
  it.each(["", ".", ".."])("refuses %j", (value) => {
    expect(() => segment(value)).toThrow(ConnectorError);
  });

  it("encodes what would change the path", () => {
    expect(segment("a/b?c#d e%")).toBe("a%2Fb%3Fc%23d%20e%25");
  });
});

describe("newLaunchDarklyApi", () => {
  it.each(["evil", "toString", "__proto__"])(
    "refuses an instance outside the three, %j, before any call",
    (instance) => {
      const fetchMock = stubFetch(async () => Response.json({}));

      expect(() =>
        newLaunchDarklyApi({
          // @ts-expect-error -- an instance outside the three, on purpose.
          instance,
          token: TOKEN,
          logger,
        })
      ).toThrow(ConnectorError);
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each([
    ["commercial", "app.launchdarkly.com"],
    ["eu", "app.eu.launchdarkly.com"],
    ["federal", "app.launchdarkly.us"],
  ] as const)(
    "calls the %s instance's host with the token as it is, the pinned API version, and no redirect followed",
    async (instance, host) => {
      const fetchMock = stubFetch(async () => Response.json({}));

      await api(instance).read({
        route: "getCallerIdentity",
        answer: z.unknown(),
      });

      const [url, init] = fetchMock.mock.calls[0] ?? [];
      expect(url).toBe(`https://${host}/api/v2/caller-identity`);
      expect(init?.method).toBe("GET");
      expect(init?.redirect).toBe("manual");
      expect(Object.fromEntries(new Headers(init?.headers))).toEqual({
        accept: "application/json",
        authorization: TOKEN,
        "ld-api-version": "20240415",
      });
    }
  );

  it("puts each path value in one segment", async () => {
    const fetchMock = stubFetch(async () => Response.json({}));

    await api().read({
      route: "getMember",
      params: { id: "a/../b" },
      answer: z.unknown(),
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe(`${API}/members/a%2F..%2Fb`);
  });

  // Among them, the routes the Enterprise accesses called: custom roles,
  // teams, projects and role attributes.
  it.each([
    "deleteMember",
    "getCustomRole",
    "getCustomRoles",
    "getTeam",
    "getTeams",
    "getProjects",
  ])(
    "refuses the read %s, outside the allowlist, before any call",
    async (route) => {
      await refusedBeforeFetch(() =>
        api().read({
          // @ts-expect-error -- not a route the connector makes, on purpose.
          route,
          answer: z.unknown(),
        })
      );
    }
  );

  it.each(["patchMembers", "patchTeam", "postMemberTeams"])(
    "refuses the write %s, outside the allowlist, before any call",
    async (route) => {
      await refusedBeforeFetch(() =>
        api().write({
          // @ts-expect-error -- not a route the connector makes, on purpose.
          route,
          body: [],
          answer: z.unknown(),
        })
      );
    }
  );

  describe("GET /members", () => {
    it("sends one email filter", async () => {
      const fetchMock = stubFetch(async () => Response.json({ items: [] }));

      await api().read({
        route: "getMembers",
        query: { filter: "email:a+b@example.com|a+b@example.com" },
        answer: ITEMS,
      });

      // The spec says a `+` has to go as `%2B`.
      expect(fetchMock.mock.calls[0]?.[0]).toBe(
        `${API}/members?filter=email%3Aa%2Bb%40example.com%7Ca%2Bb%40example.com`
      );
    });

    it.each([
      ["no filter", {}],
      ["a filter on another field", { filter: "query:alice" }],
      ["a second filter", { filter: "email:a@example.com,role:admin" }],
    ])("is refused before any call with %s", async (_case, query) => {
      const { data } = await refusedBeforeFetch(() =>
        api().read({ route: "getMembers", query, answer: ITEMS })
      );
      expect(data.message).toBe(
        "The connector refused to send LaunchDarkly GET /api/v2/members: it looks members up by one email filter only. Contact P0 support."
      );
    });
  });

  describe("writes", () => {
    it("sends a member's JSON Patch on its base role", async () => {
      const fetchMock = stubFetch(async () => Response.json({}));
      const patch = [
        { op: "test", path: "/role", value: "no_access" },
        { op: "replace", path: "/role", value: "writer" },
      ] as const;

      await api().write({
        route: "patchMember",
        params: { id: MEMBER_ID },
        body: [...patch],
        answer: z.unknown(),
      });

      const [url, init] = fetchMock.mock.calls[0] ?? [];
      expect(url).toBe(`${API}/members/${MEMBER_ID}`);
      expect(init?.method).toBe("PATCH");
      expect(new Headers(init?.headers).get("content-type")).toBe(
        "application/json"
      );
      expect(sentJson(init)).toEqual(patch);
    });

    it.each([
      ["the email", { op: "replace", path: "/email", value: EMAIL }],
      [
        "the role attributes",
        { op: "add", path: "/roleAttributes/projects", value: ["x"] },
      ],
      ["the member's teams", { op: "add", path: "/teams/-", value: "t" }],
      ["a test on another path", { op: "test", path: "/email", value: EMAIL }],
      ["a move", { op: "move", from: "/role", path: "/customRoles/0" }],
      ["a removal of the base role", { op: "remove", path: "/role" }],
      [
        "owner as a base role",
        { op: "replace", path: "/role", value: "owner" },
      ],
      ["a test for owner", { op: "test", path: "/role", value: "owner" }],
      ["an unknown base role", { op: "replace", path: "/role", value: "x" }],
      [
        "a base role that isn't a string",
        { op: "replace", path: "/role", value: ["admin"] },
      ],
      [
        "a custom role added",
        {
          op: "add",
          path: "/customRoles/-",
          value: "1234a56b7c89d012345e678f",
        },
      ],
      [
        "the whole custom role list",
        { op: "replace", path: "/customRoles", value: [] },
      ],
      ["a custom role removed", { op: "remove", path: "/customRoles/0" }],
      ["a test on the version", { op: "test", path: "/version", value: 3 }],
    ])(
      "refuses a member JSON Patch on %s before any call",
      async (_case, operation) => {
        const { data } = await refusedBeforeFetch(() =>
          api().write({
            route: "patchMember",
            params: { id: MEMBER_ID },
            body: [
              { op: "replace", path: "/role", value: "reader" },
              // @ts-expect-error -- outside the allowlist on purpose, so outside its types too.
              operation,
            ],
            answer: z.unknown(),
          })
        );
        expect(data.message).toBe(
          "The connector refused to send LaunchDarkly PATCH /api/v2/members/{id}: its body isn't one the connector sends. Contact P0 support."
        );
      }
    );
  });

  describe("answers", () => {
    it.each([301, 302, 307])(
      "fails on a %i, reading nothing of its body",
      async (status) => {
        const { stream, body } = streamed(4);
        const fetchMock = stubFetch(async () => new Response(body, { status }));

        const error = await launchDarklyError(() =>
          api().read({ route: "getCallerIdentity", answer: z.unknown() })
        );

        expect(error.failure).toEqual({ kind: "status", status });
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(stream.pulled).toBe(0);
      }
    );

    it("reads LaunchDarkly's code from an error, and its message on a write only", async () => {
      stubFetch(async () =>
        Response.json(
          { code: "invalid_request", message: "bad\npatch", id: "x-1" },
          { status: 400 }
        )
      );

      const read = await launchDarklyError(() =>
        api().read({ route: "getCallerIdentity", answer: z.unknown() })
      );
      const write = await launchDarklyError(() =>
        api().write({
          route: "patchMember",
          params: { id: MEMBER_ID },
          body: [{ op: "replace", path: "/role", value: "writer" }],
          answer: z.unknown(),
        })
      );

      expect(read.failure).toEqual({
        kind: "status",
        status: 400,
        code: "invalid_request",
      });
      expect(write.failure).toEqual({
        kind: "status",
        status: 400,
        code: "invalid_request",
        message: "bad patch",
      });
    });

    it("reads at most its cap of an answer, and fails past it", async () => {
      const { stream, body } = streamed(MAX_ANSWER_BYTES / (16 * 1024) + 10);
      stubFetch(async () => new Response(body));

      const error = await launchDarklyError(() =>
        api().read({ route: "getCallerIdentity", answer: z.unknown() })
      );

      expect(error.failure).toEqual({
        kind: "unexpected",
        reason: "too_large",
      });
      expect(stream.pulled).toBe(MAX_ANSWER_BYTES / (16 * 1024) + 1);
      expect(stream.cancelled).toBe(true);
    });

    it.each([
      ["isn't JSON", () => new Response("<html>"), "not_json"],
      ["isn't the shape", () => Response.json({ rows: [] }), "wrong_shape"],
    ] as const)("fails when the answer %s", async (_case, answer, reason) => {
      stubFetch(async () => answer());

      const error = await launchDarklyError(() =>
        api().read({
          route: "getMembers",
          query: { filter: `email:${EMAIL}` },
          answer: ITEMS,
        })
      );

      expect(error.failure).toEqual({ kind: "unexpected", reason });
    });

    it("fails as unreachable when the connection is refused", async () => {
      stubFetch(async () => {
        throw new TypeError("fetch failed", {
          cause: Object.assign(new Error("refused"), { code: "ECONNREFUSED" }),
        });
      });

      const error = await launchDarklyError(() =>
        api().read({ route: "getCallerIdentity", answer: z.unknown() })
      );

      expect(error.failure).toEqual({
        kind: "unreachable",
        timedOut: false,
        code: "ECONNREFUSED",
      });
    });
  });

  // `GET /members` carries an email in its query, and a member's path its
  // id: the error and the log lines name the call by its route only, and
  // none of them holds the token.
  it.each<[string, Fetch]>([
    ["succeeds", async () => Response.json({ items: [] })],
    [
      "LaunchDarkly echoes the request",
      async () =>
        Response.json(
          { code: "invalid_request", message: `${EMAIL} ${TOKEN}` },
          { status: 400 }
        ),
    ],
    [
      "the call fails, quoting the request",
      async () => {
        throw new TypeError(
          `fetch failed ${API}/members?filter=email:${EMAIL}`,
          { cause: new Error(`socket hang up Authorization: ${TOKEN}`) }
        );
      },
    ],
  ])(
    "shows no token or email in an error or a log line when the call %s",
    async (_case, answer) => {
      const log = recordLogger();
      stubFetch(answer);

      const outcome = await api()
        .read({
          route: "getMembers",
          query: { filter: `email:${EMAIL}` },
          answer: ITEMS,
        })
        .catch((error: unknown) => error);

      expect(log.lines()).not.toHaveLength(0);
      const seen = log.seen(outcome, inspect(outcome));
      for (const marker of NEVER_SHOWN) {
        expect(seen).not.toContain(marker);
      }
    }
  );
});
