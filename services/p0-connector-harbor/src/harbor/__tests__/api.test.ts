import { ConnectorError } from "@p0security/connector";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  AUTHORIZATION,
  ID_TOKEN,
  NEVER_SHOWN,
  logger,
  propertySeed,
  recordLogger,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import {
  type HarborCall,
  HarborError,
  type HarborFailure,
  MAX_ANSWER_BYTES,
  newHarborApi,
  segment,
} from "../api.ts";
import { ORIGIN } from "./fake-harbor.ts";

const CALL = {
  method: "GET",
  route: "/api/v2.0/projects/{project_name}/members",
} as const satisfies HarborCall;

const ROWS = z.array(z.object({ id: z.number() }));

type Fetch = (url: string, init: RequestInit) => Promise<Response>;

const stubFetch = (answer: Fetch) => {
  const mock = vi.fn(answer);
  vi.stubGlobal("fetch", mock);
  return mock;
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

const api = () => newHarborApi({ origin: ORIGIN, idToken: ID_TOKEN, logger });

/** The {@link HarborError} `run` fails with. Anything else fails the test. */
const harborError = async (run: () => Promise<unknown>) => {
  const outcome = await run().then(
    () => new Error("expected the call to throw"),
    (error: unknown) => error
  );
  if (outcome instanceof HarborError) return outcome;
  throw outcome;
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

/** How `fetch` fails: a bare "fetch failed", with what happened as its cause. */
const fetchFailure = (code?: string) =>
  new TypeError("fetch failed", {
    cause: Object.assign(new Error(`${code} (${AUTHORIZATION})`), {
      ...(code === undefined ? {} : { code }),
    }),
  });

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

  // Whatever the string, it is one segment that decodes back to itself, or
  // it is refused.
  const seed = propertySeed();
  it(
    `keeps any string one segment, or refuses it (PROPERTY_SEED=${seed})`,
    // Thousands of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    () => {
      const random = seededRandom(seed);
      const alphabet = ["a", ".", "/", "%", "?", "#", " ", "\\", "é", "\u0000"];
      for (let i = 0; i < 2000; i++) {
        const value = Array.from(
          { length: Math.floor(random() * 4) },
          () => alphabet[Math.floor(random() * alphabet.length)]
        ).join("");
        if (value === "" || value === "." || value === "..") {
          expect(() => segment(value)).toThrow(ConnectorError);
          continue;
        }
        const encoded = segment(value);
        expect(encoded).not.toMatch(/[/?#\\]/);
        expect(decodeURIComponent(encoded)).toBe(value);
      }
    }
  );
});

describe("newHarborApi", () => {
  it("refuses an origin that isn't https", () => {
    expect(() =>
      newHarborApi({
        origin: "http://harbor.example.com",
        idToken: ID_TOKEN,
        logger,
      })
    ).toThrow(ConnectorError);
  });

  it("calls the origin's API with the ID token, names resources by name, and reads the answer", async () => {
    const fetchMock = stubFetch(async () => json([{ id: 1 }]));

    const data = await api().read({
      call: CALL,
      path: "/projects/library/members",
      query: { page: "2", page_size: "100" },
      answer: ROWS,
    });

    expect(data).toEqual([{ id: 1 }]);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(
      `${ORIGIN}/api/v2.0/projects/library/members?page=2&page_size=100`
    );
    expect(init?.method).toBe("GET");
    expect(init?.body).toBeUndefined();
    expect(Object.fromEntries(new Headers(init?.headers))).toEqual({
      accept: "application/json",
      authorization: AUTHORIZATION,
      "x-is-resource-name": "true",
    });
  });

  it("sends a body as JSON", async () => {
    const fetchMock = stubFetch(
      async () => new Response(null, { status: 201 })
    );

    await expect(
      api().send({
        call: { ...CALL, method: "POST" },
        path: "/projects/library/members",
        body: { role_id: 3 },
      })
    ).resolves.toBeUndefined();

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.body).toBe('{"role_id":3}');
    expect(new Headers(init?.headers).get("content-type")).toBe(
      "application/json"
    );
  });

  // A stub can't follow a redirect or run out of time. What holds both is
  // what the call is given.
  it("gives Harbor 10 seconds, and follows no redirect", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    const fetchMock = stubFetch(async () => json([]));

    await api().read({ call: CALL, path: "/x", answer: ROWS });

    expect(timeout).toHaveBeenCalledWith(10_000);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        redirect: "manual",
        signal: timeout.mock.results[0]?.value,
      })
    );
  });

  it.each([301, 307, 401, 403, 404, 409, 429, 500, 503])(
    "fails with the status, and reads nothing of the body, on %i",
    async (status) => {
      const { stream, body } = streamed(4);
      stubFetch(async () => new Response(body, { status }));

      const error = await harborError(() =>
        api().read({ call: CALL, path: "/x", answer: ROWS })
      );

      expect(error.failure).toEqual({ kind: "status", status });
      expect(error.call).toBe(CALL);
      expect(stream.pulled).toBe(0);
      expect(stream.cancelled).toBe(true);
    }
  );

  it("reads nothing of the body when there's no answer to check", async () => {
    const { stream, body } = streamed(4);
    stubFetch(async () => new Response(body, { status: 200 }));

    await api().send({ call: CALL, path: "/x" });

    expect(stream.pulled).toBe(0);
    expect(stream.cancelled).toBe(true);
  });

  it("reads up to 1 MiB, and fails past that", async () => {
    const { stream, body } = streamed(1024);
    stubFetch(async () => new Response(body));

    const error = await harborError(() =>
      api().read({ call: CALL, path: "/x", answer: ROWS })
    );

    expect(error.failure).toEqual({ kind: "unexpected", reason: "too_large" });
    // 64 chunks fill the cap, and the 65th is the one over it.
    expect(MAX_ANSWER_BYTES / (16 * 1024)).toBe(64);
    expect(stream.pulled).toBe(65);
    expect(stream.cancelled).toBe(true);
  });

  it("reads an answer of exactly 1 MiB", async () => {
    const text = "[]".padEnd(MAX_ANSWER_BYTES, " ");
    stubFetch(async () => new Response(text));

    await expect(
      api().read({ call: CALL, path: "/x", answer: ROWS })
    ).resolves.toEqual([]);
  });

  it.each<[string, () => Response, HarborFailure]>([
    [
      "isn't JSON",
      () => new Response("<html>"),
      { kind: "unexpected", reason: "not_json" },
    ],
    [
      "isn't the shape",
      () => json({ rows: [] }),
      { kind: "unexpected", reason: "wrong_shape" },
    ],
  ])("fails when the answer %s", async (_case, answer, failure) => {
    stubFetch(async () => answer());

    const error = await harborError(() =>
      api().read({ call: CALL, path: "/x", answer: ROWS })
    );

    expect(error.failure).toEqual(failure);
  });

  it.each<[string, unknown, HarborFailure]>([
    [
      "the connection is refused",
      fetchFailure("ECONNREFUSED"),
      { kind: "unreachable", timedOut: false, code: "ECONNREFUSED" },
    ],
    [
      "the host doesn't resolve",
      fetchFailure("ENOTFOUND"),
      { kind: "unreachable", timedOut: false, code: "ENOTFOUND" },
    ],
    [
      "it says nothing about itself",
      fetchFailure(),
      { kind: "unreachable", timedOut: false },
    ],
    [
      "there's no answer in time",
      new DOMException(
        "The operation was aborted due to timeout",
        "TimeoutError"
      ),
      { kind: "unreachable", timedOut: true, name: "TimeoutError" },
    ],
  ])("fails as unreachable when %s", async (_case, failure, expected) => {
    stubFetch(async () => {
      throw failure;
    });

    const error = await harborError(() =>
      api().read({ call: CALL, path: "/x", answer: ROWS })
    );

    // A DOMException carries a legacy numeric code as well.
    expect(error.failure).toMatchObject(expected);
  });

  it("fails as unreachable when the answer breaks off", async () => {
    stubFetch(
      async () =>
        new Response(
          new ReadableStream({
            start: (controller) => {
              controller.error(
                Object.assign(new TypeError("terminated"), {
                  code: "UND_ERR_SOCKET",
                })
              );
            },
          })
        )
    );

    const error = await harborError(() =>
      api().read({ call: CALL, path: "/x", answer: ROWS })
    );

    expect(error.failure).toMatchObject({
      kind: "unreachable",
      code: "UND_ERR_SOCKET",
    });
  });

  it("names the call by its route in the error, and keeps nothing of the request", async () => {
    stubFetch(async () => {
      throw fetchFailure("ECONNRESET");
    });

    const error = await harborError(() =>
      api().read({
        call: CALL,
        path: "/projects/secret-project/members",
        query: { email: "someone@example.com" },
        answer: ROWS,
      })
    );

    expect(error.message).toBe(
      "Harbor GET /api/v2.0/projects/{project_name}/members: no answer (ECONNRESET)"
    );
    expect(error.cause).toBeUndefined();
    const shown = inspect(error);
    expect(shown).not.toContain("secret-project");
    expect(shown).not.toContain("someone@example.com");
    expect(shown).not.toContain(ID_TOKEN);
  });

  // A path carries a project's name and a query an email: the log lines name
  // the call by its route only.
  it.each<[string, Fetch]>([
    ["succeeds", async () => json([])],
    ["fails", async () => json({}, 500)],
  ])("logs no path or query value when the call %s", async (_case, answer) => {
    const log = recordLogger();
    stubFetch(answer);

    await api()
      .read({
        call: CALL,
        path: "/projects/secret-project/members",
        query: { email: "someone@example.com" },
        answer: ROWS,
      })
      .catch(() => undefined);

    expect(log.lines()).not.toHaveLength(0);
    const seen = log.seen();
    expect(seen).not.toContain("secret-project");
    expect(seen).not.toContain("someone@example.com");
  });

  describe("its log lines", () => {
    // The caller decides what a status means: a 404 from HEAD /projects is
    // an answer, and a 409 on a POST is read again.
    it.each([403, 404, 409])(
      "note a %i at debug, not as a warning",
      async (status) => {
        const warn = vi.spyOn(logger, "warn");
        const debug = vi.spyOn(logger, "debug");
        stubFetch(async () => json({}, status));

        await harborError(() => api().send({ call: CALL, path: "/x" }));

        expect(warn).not.toHaveBeenCalled();
        expect(debug).toHaveBeenCalledWith(
          { method: "GET", route: CALL.route, status },
          expect.any(String)
        );
      }
    );

    it.each<[string, () => Response, string]>([
      ["isn't JSON", () => new Response("<html>"), "not_json"],
      ["isn't the shape", () => json({ rows: [] }), "wrong_shape"],
    ])(
      "warn with the reason when the answer %s",
      async (_case, answer, reason) => {
        const warn = vi.spyOn(logger, "warn");
        stubFetch(async () => answer());

        await harborError(() =>
          api().read({ call: CALL, path: "/x", answer: ROWS })
        );

        expect(warn).toHaveBeenCalledWith(
          expect.objectContaining({ route: CALL.route, reason }),
          expect.any(String)
        );
      }
    );

    it("warn with the reason for a check the caller makes", () => {
      const warn = vi.spyOn(logger, "warn");

      const error = api().unexpected(CALL, "endless");

      expect(error.failure).toEqual({ kind: "unexpected", reason: "endless" });
      expect(error.call).toBe(CALL);
      expect(warn).toHaveBeenCalledWith(
        expect.objectContaining({ route: CALL.route, reason: "endless" }),
        expect.any(String)
      );
    });

    it("warn when a call gets no answer", async () => {
      const warn = vi.spyOn(logger, "warn");
      stubFetch(async () => {
        throw fetchFailure("ECONNRESET");
      });

      await harborError(() => api().send({ call: CALL, path: "/x" }));

      expect(warn).toHaveBeenCalledWith(
        expect.objectContaining({
          route: CALL.route,
          kind: "unreachable",
          code: "ECONNRESET",
        }),
        expect.any(String)
      );
    });
  });

  describe("the credential", () => {
    const OUTCOMES: [string, Fetch][] = [
      ["the call succeeds", async () => json([{ id: 1 }])],
      ["Harbor refuses it", async () => json({ message: ID_TOKEN }, 403)],
      [
        "the answer isn't the shape, and quotes the request",
        async () => json([{ id: AUTHORIZATION, secret: ID_TOKEN }]),
      ],
      [
        "the call fails, quoting the request",
        async () => {
          throw new TypeError(`fetch failed ${AUTHORIZATION}`, {
            cause: new Error(`socket hang up ${AUTHORIZATION}`),
          });
        },
      ],
    ];

    it.each(OUTCOMES)(
      "reaches no log line and no error when %s",
      async (_case, answer) => {
        const log = recordLogger();
        stubFetch(answer);

        const outcome = await api()
          .read({
            call: CALL,
            path: "/x",
            answer: ROWS,
          })
          .catch((error: unknown) => error);

        expect(log.lines()).not.toHaveLength(0);
        const seen = log.seen(outcome);
        for (const marker of [...NEVER_SHOWN, ID_TOKEN]) {
          expect(seen).not.toContain(marker);
        }
      }
    );
  });

  // Harbor's bytes are the vendor's. Whatever they are, the call returns
  // what the schema allows or fails with a HarborError, and logs none of
  // them.
  const seed = propertySeed();
  it(
    `returns what the schema allows, or a HarborError, for any answer (PROPERTY_SEED=${seed})`,
    // Thousands of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    async () => {
      const random = seededRandom(seed);
      const pick = <T>(values: readonly T[]): T =>
        values[Math.floor(random() * values.length)] as T;
      const MARKER = "SENTINEL-vendor-bytes";
      const value = (depth: number): unknown =>
        pick([
          () => null,
          () => Math.floor(random() * 2e9) - 1e9,
          () => random(),
          () => `${MARKER}-${Math.floor(random() * 100)}`,
          () => random() < 0.5,
          () =>
            depth > 2
              ? []
              : Array.from({ length: Math.floor(random() * 4) }, () =>
                  value(depth + 1)
                ),
          () =>
            depth > 2
              ? {}
              : Object.fromEntries(
                  Array.from({ length: Math.floor(random() * 3) }, () => [
                    pick(["id", "name", MARKER]),
                    value(depth + 1),
                  ])
                ),
        ])();
      const body = (): ConstructorParameters<typeof Response>[0] =>
        pick([
          () => JSON.stringify(value(0)),
          () => JSON.stringify(value(0)).slice(0, Math.floor(random() * 10)),
          () =>
            new Uint8Array(Math.floor(random() * 64)).map(() =>
              Math.floor(random() * 256)
            ),
          () => "",
        ])();

      const log = recordLogger();
      const errors: unknown[] = [];
      for (let i = 0; i < 500; i++) {
        const status = pick([200, 200, 200, 201, 204, 302, 404, 500]);
        stubFetch(
          async () =>
            new Response(status === 204 || status === 302 ? null : body(), {
              status,
            })
        );

        const outcome = await api()
          .read({
            call: CALL,
            path: "/x",
            answer: ROWS,
          })
          .catch((error: unknown) => error);

        if (outcome instanceof HarborError) {
          expect(["status", "unexpected"]).toContain(outcome.failure.kind);
          errors.push(outcome);
        } else {
          expect(ROWS.safeParse(outcome).success).toBe(true);
        }
      }
      expect(log.seen(errors)).not.toContain(MARKER);
    }
  );
});
