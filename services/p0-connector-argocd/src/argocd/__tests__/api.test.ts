// copy of services/p0-connector-harbor/src/harbor/__tests__/api.test.ts, for
// Argo CD's bearer token, its route prefixes and its `**` path parts
import { ConnectorError } from "@p0security/connector-core";
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  NEVER_SHOWN,
  TOKEN,
  connectorError,
  logger,
  propertySeed,
  recordLogger,
  seededRandom,
} from "../../__tests__/fixtures.ts";
import {
  type ArgoCdCall,
  ArgoCdError,
  type ArgoCdFailure,
  MAX_ANSWER_BYTES,
  isStatus,
  newArgoCdApi,
  pathParts,
  segment,
} from "../api.ts";
import { ARGOCD_ORIGIN, BEARER } from "./fake-argocd.ts";

const CALL = {
  method: "GET",
  route: "/api/v1/applications/{name}",
  permission: "applications, get",
} as const satisfies ArgoCdCall;

const ROWS = z.array(z.object({ id: z.number() }));

type Fetch = (url: string, init: RequestInit) => Promise<Response>;

const stubFetch = (answer: Fetch) => {
  const mock = vi.fn(answer);
  vi.stubGlobal("fetch", mock);
  return mock;
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

const api = (token = TOKEN) =>
  newArgoCdApi({ origin: ARGOCD_ORIGIN, token, logger });

/** The {@link ArgoCdError} `run` fails with. Anything else fails the test. */
const argoCdError = async (run: () => Promise<unknown>) => {
  const outcome = await run().then(
    () => new Error("expected the call to throw"),
    (error: unknown) => error
  );
  if (outcome instanceof ArgoCdError) return outcome;
  throw outcome;
};

/** A body of `chunks` 64 KiB chunks, which counts the chunks it was asked for. */
const CHUNK = 64 * 1024;
const streamed = (chunks: number) => {
  const stream = { pulled: 0, cancelled: false };
  const body = new ReadableStream<Uint8Array>(
    {
      pull: (controller) => {
        if (stream.pulled === chunks) return controller.close();
        stream.pulled += 1;
        controller.enqueue(new Uint8Array(CHUNK).fill(0x20));
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
    cause: Object.assign(new Error(`${code} (${BEARER})`), {
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

describe("ArgoCdError", () => {
  it.each<[ArgoCdFailure, string]>([
    [{ kind: "unreachable", timedOut: true }, "no answer in time"],
    [
      { kind: "unreachable", timedOut: false, code: "ECONNRESET" },
      "no answer (ECONNRESET)",
    ],
    [{ kind: "unreachable", timedOut: false }, "no answer (unknown)"],
    [{ kind: "anonymous" }, "answered as to an anonymous caller"],
    [
      { kind: "not_managed", app: "argocd", namespace: "argocd" },
      "the Application doesn't manage the resource",
    ],
    [{ kind: "status", status: 418 }, "answered 418"],
    [
      { kind: "unexpected", reason: "not_json" },
      "unexpected answer (not_json)",
    ],
  ])("says how the call failed: %j", (failure, said) => {
    const error = new ArgoCdError(CALL, failure);

    expect(error.message).toBe(
      `Argo CD GET /api/v1/applications/{name}: ${said}`
    );
    expect(error.name).toBe("ArgoCdError");
  });
});

describe("isStatus", () => {
  it("is whether an Argo CD call answered that status", () => {
    const answered = new ArgoCdError(CALL, { kind: "status", status: 400 });

    expect(isStatus(answered, 400)).toBe(true);
    expect(isStatus(answered, 404)).toBe(false);
    expect(isStatus(new ArgoCdError(CALL, { kind: "anonymous" }), 400)).toBe(
      false
    );
  });

  // A refused name fails before any call, with a ConnectorError.
  it.each([
    new ConnectorError({ type: "unknown", message: "x", payload: {} }),
    new Error("x"),
    undefined,
  ])("is false for anything else: %s", (error) => {
    expect(isStatus(error, 400)).toBe(false);
  });
});

describe("segment", () => {
  it.each(["", ".", ".."])("refuses %j", (value) => {
    expect(() => segment(value)).toThrow(ConnectorError);
  });

  it("says why, naming the segment", async () => {
    const error = await connectorError(async () => segment(".."));

    expect(error.data).toEqual({
      type: "validation_error",
      message: `".." isn't a valid Argo CD name.`,
      payload: { segment: ".." },
    });
  });

  it("encodes what would change the path", () => {
    expect(segment("a/b?c#d e%")).toBe("a%2Fb%3Fc%23d%20e%25");
  });
});

describe("pathParts", () => {
  it.each([
    ["*/*", "*/*"],
    ["*", "*"],
    ["platform/argocd", "platform/argocd"],
    ["a b/c?d", "a%20b/c%3Fd"],
  ])("keeps the slashes of %j", (value, expected) => {
    expect(pathParts(value)).toBe(expected);
  });

  it.each(["", "/", "a/", "/a", "a//b", "a/../b", "./a", "a/."])(
    "refuses %j",
    (value) => {
      expect(() => pathParts(value)).toThrow(ConnectorError);
    }
  );

  // Whatever the string, it is the same pieces between its slashes, each of
  // which decodes back to itself, or it is refused.
  const seed = propertySeed();
  it(
    `keeps any string's pieces apart, or refuses it (PROPERTY_SEED=${seed})`,
    // Thousands of cases, which a loaded machine can take seconds over.
    { timeout: 30_000 },
    () => {
      const random = seededRandom(seed);
      const alphabet = ["a", "*", ".", "/", "%", "?", "#", " ", "\\", "é"];
      for (let i = 0; i < 3000; i++) {
        const value = Array.from(
          { length: Math.floor(random() * 6) },
          () => alphabet[Math.floor(random() * alphabet.length)]
        ).join("");
        const pieces = value.split("/");
        if (pieces.some((piece) => ["", ".", ".."].includes(piece))) {
          expect(() => pathParts(value)).toThrow(ConnectorError);
          continue;
        }
        const encoded = pathParts(value);
        const encodedPieces = encoded.split("/");
        expect(encoded).not.toMatch(/[?#\\]|%2F/i);
        expect(encodedPieces.map(decodeURIComponent)).toEqual(pieces);
      }
    }
  );
});

describe("newArgoCdApi", () => {
  it("refuses an origin that isn't https, saying so", async () => {
    const error = await connectorError(async () =>
      newArgoCdApi({
        origin: "http://argocd.example.com",
        token: TOKEN,
        logger,
      })
    );

    expect(error.data).toEqual({
      type: "validation_error",
      message: "The connector only calls Argo CD over https.",
      payload: {},
    });
  });

  it("refuses an origin that isn't https", () => {
    expect(() =>
      newArgoCdApi({
        origin: "http://argocd.example.com",
        token: TOKEN,
        logger,
      })
    ).toThrow(ConnectorError);
  });

  it("calls the origin's API with the bearer token, and reads the answer", async () => {
    const fetchMock = stubFetch(async () => json([{ id: 1 }]));

    const data = await api().read({
      call: CALL,
      path: "/api/v1/applications/argocd/resource",
      query: { namespace: "argocd", group: "" },
      answer: ROWS,
    });

    expect(data).toEqual([{ id: 1 }]);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(
      `${ARGOCD_ORIGIN}/api/v1/applications/argocd/resource?namespace=argocd&group=`
    );
    expect(init?.method).toBe("GET");
    expect(init?.body).toBeUndefined();
    expect(Object.fromEntries(new Headers(init?.headers))).toEqual({
      accept: "application/json",
      authorization: BEARER,
    });
  });

  it("calls a route outside /api/v1 as it is", async () => {
    const fetchMock = stubFetch(async () => json([]));

    await api().read({
      call: { method: "GET", route: "/api/version" },
      path: "/api/version",
      answer: ROWS,
    });

    expect(fetchMock.mock.calls[0]?.[0]).toBe(`${ARGOCD_ORIGIN}/api/version`);
  });

  it("sends a body as JSON, once", async () => {
    const fetchMock = stubFetch(async () => json({}));

    await expect(
      api().send({
        call: { ...CALL, method: "POST" },
        path: "/api/v1/applications/argocd/resource",
        body: '{"data":{}}',
      })
    ).resolves.toBeUndefined();

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(init?.body).toBe('"{\\"data\\":{}}"');
    expect(new Headers(init?.headers).get("content-type")).toBe(
      "application/json"
    );
  });

  // A stub can't follow a redirect or run out of time. What holds both is
  // what the call is given.
  it("gives Argo CD 10 seconds, and follows no redirect", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    const fetchMock = stubFetch(async () => json([]));

    await api().read({ call: CALL, path: "/api/v1/x", answer: ROWS });

    expect(timeout).toHaveBeenCalledWith(10_000);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        redirect: "manual",
        signal: timeout.mock.results[0]?.value,
      })
    );
  });

  it.each([300, 301, 307, 400, 401, 403, 404, 409, 429, 500, 503])(
    "fails with the status, and reads nothing of the body, on %i",
    async (status) => {
      const { stream, body } = streamed(4);
      stubFetch(async () => new Response(body, { status }));

      const error = await argoCdError(() =>
        api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
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

    await api().send({ call: CALL, path: "/api/v1/x" });

    expect(stream.pulled).toBe(0);
    expect(stream.cancelled).toBe(true);
  });

  it("reads up to 4 MiB, and fails past that", async () => {
    const { stream, body } = streamed(1024);
    stubFetch(async () => new Response(body));

    const error = await argoCdError(() =>
      api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
    );

    expect(error.failure).toEqual({ kind: "unexpected", reason: "too_large" });
    // 64 chunks fill the cap, and the 65th is the one over it.
    expect(MAX_ANSWER_BYTES / CHUNK).toBe(64);
    expect(stream.pulled).toBe(65);
    expect(stream.cancelled).toBe(true);
  });

  it("reads an answer of exactly 4 MiB", async () => {
    const text = "[]".padEnd(MAX_ANSWER_BYTES, " ");
    stubFetch(async () => new Response(text));

    await expect(
      api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
    ).resolves.toEqual([]);
  });

  it.each<[string, () => Response, ArgoCdFailure]>([
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

    const error = await argoCdError(() =>
      api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
    );

    expect(error.failure).toEqual(failure);
  });

  it.each<[string, unknown, ArgoCdFailure]>([
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

    const error = await argoCdError(() =>
      api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
    );

    // A DOMException carries a legacy numeric code as well.
    expect(error.failure).toMatchObject(expected);
  });

  // A fact Node didn't give isn't a key at all, so no log line carries an
  // `undefined`.
  it("keeps only the facts a failure has", async () => {
    stubFetch(async () => {
      throw fetchFailure();
    });

    const error = await argoCdError(() =>
      api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
    );

    expect(Object.keys(error.failure)).toEqual(["kind", "timedOut"]);
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

    const error = await argoCdError(() =>
      api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
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

    const error = await argoCdError(() =>
      api().read({
        call: CALL,
        path: "/api/v1/applications/secret-app",
        query: { namespace: "secret-namespace" },
        answer: ROWS,
      })
    );

    expect(error.message).toBe(
      "Argo CD GET /api/v1/applications/{name}: no answer (ECONNRESET)"
    );
    expect(error.cause).toBeUndefined();
    const shown = inspect(error);
    expect(shown).not.toContain("secret-app");
    expect(shown).not.toContain("secret-namespace");
    expect(shown).not.toContain(TOKEN);
  });

  // A path carries an Application's name and a query a namespace: the log
  // lines name the call by its route only.
  it.each<[string, Fetch]>([
    ["succeeds", async () => json([])],
    ["fails", async () => json({}, 500)],
  ])("logs no path or query value when the call %s", async (_case, answer) => {
    const log = recordLogger();
    stubFetch(answer);

    await api()
      .read({
        call: CALL,
        path: "/api/v1/applications/secret-app",
        query: { namespace: "secret-namespace" },
        answer: ROWS,
      })
      .catch(() => undefined);

    expect(log.lines()).not.toHaveLength(0);
    const seen = log.seen();
    expect(seen).not.toContain("secret-app");
    expect(seen).not.toContain("secret-namespace");
  });

  describe("its log lines", () => {
    // The caller decides what a status means: a 404 from a resource route is
    // an answer.
    it.each([403, 404])(
      "note a %i at debug, not as a warning",
      async (status) => {
        const warn = vi.spyOn(logger, "warn");
        const debug = vi.spyOn(logger, "debug");
        stubFetch(async () => json({}, status));

        await argoCdError(() => api().send({ call: CALL, path: "/api/v1/x" }));

        expect(warn).not.toHaveBeenCalled();
        expect(debug).toHaveBeenCalledWith(
          { method: "GET", route: CALL.route, status },
          expect.any(String)
        );
      }
    );

    it("note a success at debug", async () => {
      const debug = vi.spyOn(logger, "debug");
      stubFetch(async () => json([]));

      await api().read({ call: CALL, path: "/api/v1/x", answer: ROWS });

      expect(debug).toHaveBeenCalledWith(
        { method: "GET", route: CALL.route, status: 200 },
        expect.any(String)
      );
    });

    it.each<[string, () => Response, string]>([
      ["isn't JSON", () => new Response("<html>"), "not_json"],
      ["isn't the shape", () => json({ rows: [] }), "wrong_shape"],
    ])(
      "warn with the reason when the answer %s",
      async (_case, answer, reason) => {
        const warn = vi.spyOn(logger, "warn");
        stubFetch(async () => answer());

        await argoCdError(() =>
          api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
        );

        expect(warn).toHaveBeenCalledWith(
          expect.objectContaining({ route: CALL.route, reason }),
          expect.any(String)
        );
      }
    );

    it("warn with where the answer went wrong", async () => {
      const warn = vi.spyOn(logger, "warn");
      stubFetch(async () => json([{ id: "x" }]));

      await argoCdError(() =>
        api().read({ call: CALL, path: "/api/v1/x", answer: ROWS })
      );

      expect(warn).toHaveBeenCalledWith(
        expect.objectContaining({
          issues: [{ code: "invalid_type", path: "0.id" }],
        }),
        expect.any(String)
      );
    });

    it("warn with the reason for a check the caller makes", () => {
      const warn = vi.spyOn(logger, "warn");

      const error = api().unexpected(CALL, "wrong_shape");

      expect(error.failure).toEqual({
        kind: "unexpected",
        reason: "wrong_shape",
      });
      expect(error.call).toBe(CALL);
      expect(warn).toHaveBeenCalledWith(
        expect.objectContaining({ route: CALL.route, reason: "wrong_shape" }),
        expect.any(String)
      );
    });

    it("warn when a call gets no answer", async () => {
      const warn = vi.spyOn(logger, "warn");
      stubFetch(async () => {
        throw fetchFailure("ECONNRESET");
      });

      await argoCdError(() => api().send({ call: CALL, path: "/api/v1/x" }));

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

  describe("the token", () => {
    it("is sent trimmed", async () => {
      const fetchMock = stubFetch(async () => json([]));

      await api(`\n ${TOKEN}\r\n`).read({
        call: CALL,
        path: "/api/v1/x",
        answer: ROWS,
      });

      expect(
        new Headers(fetchMock.mock.calls[0]?.[1]?.headers).get("authorization")
      ).toBe(BEARER);
    });

    it.each([
      ["empty", ""],
      ["only whitespace", " \n\t "],
      ["split by a space", `${TOKEN} ${TOKEN}`],
      ["split by a newline", `${TOKEN}\n${TOKEN}`],
      ["holding a tab", `${TOKEN}\t1`],
      ["holding a NUL", `${TOKEN}\u00001`],
      ["holding DEL", `${TOKEN}\u007f`],
      ["holding a non-ASCII letter", `${TOKEN}é`],
      ["holding a non-breaking space", `${TOKEN}\u00a01`],
    ])(
      "is refused before any call when it is %s, and isn't repeated",
      async (_case, token) => {
        const fetchMock = stubFetch(async () => json([]));
        const log = recordLogger();

        const error = await connectorError(async () => api(token));

        expect(error.data).toEqual({
          type: "validation_error",
          message:
            "The connector's Argo CD API token is empty, or has a space, a control character or a non-ASCII character in it. Store the p0-connector account's API token exactly as Argo CD generated it.",
          payload: {},
        });
        expect(fetchMock).not.toHaveBeenCalled();
        expect(log.seen(error)).not.toContain(TOKEN.slice(0, 12));
      }
    );

    // A token goes in the header exactly as it is once trimmed, when that is
    // printable ASCII, and is refused otherwise.
    const seed = propertySeed();
    it(
      `is sent trimmed when it is printable ASCII, and refused otherwise (PROPERTY_SEED=${seed})`,
      { timeout: 30_000 },
      async () => {
        const random = seededRandom(seed);
        const pick = <T>(values: readonly T[]): T =>
          values[Math.floor(random() * values.length)] as T;
        const EDGE = [" ", "\n", "\r", "\t", "\v", "\f", " ", " ", "﻿"];
        const BODY = [
          "a",
          "Z",
          "0",
          ".",
          "-",
          "_",
          "~",
          "!",
          "\u007f",
          "\u0000",
          "é",
          "\u001b",
          ...EDGE,
        ];
        const fetchMock = stubFetch(async () => json([]));
        for (let i = 0; i < 2000; i++) {
          const middle = Array.from({ length: Math.floor(random() * 6) }, () =>
            pick(random() < 0.8 ? ["a", "Z", "0", ".", "-", "_"] : BODY)
          ).join("");
          const edges = () =>
            Array.from({ length: Math.floor(random() * 3) }, () =>
              pick(EDGE)
            ).join("");
          const token = `${edges()}${middle}${edges()}`;
          fetchMock.mockClear();

          const outcome = await Promise.resolve()
            .then(() =>
              api(token).read({ call: CALL, path: "/api/v1/x", answer: ROWS })
            )
            .then(
              () => "sent",
              (error: unknown) => error
            );

          // Trimmed by hand: JavaScript's whitespace, written out.
          const isSpace = (c: string) => EDGE.includes(c) || c === " ";
          let start = 0;
          let end = token.length;
          while (start < end && isSpace(token[start] ?? "")) start++;
          while (end > start && isSpace(token[end - 1] ?? "")) end--;
          const trimmed = token.slice(start, end);
          const printable =
            trimmed.length > 0 &&
            [...trimmed].every((c) => c >= "!" && c <= "~");
          if (printable) {
            expect(outcome).toBe("sent");
            expect(
              new Headers(fetchMock.mock.calls[0]?.[1]?.headers).get(
                "authorization"
              )
            ).toBe(`Bearer ${trimmed}`);
          } else {
            expect(outcome).toBeInstanceOf(ConnectorError);
            expect(fetchMock).not.toHaveBeenCalled();
          }
        }
      }
    );

    const OUTCOMES: [string, Fetch][] = [
      ["the call succeeds", async () => json([{ id: 1 }])],
      ["Argo CD refuses it", async () => json({ message: TOKEN }, 403)],
      [
        "the answer isn't the shape, and quotes the request",
        async () => json([{ id: BEARER, token: TOKEN }]),
      ],
      [
        "the call fails, quoting the request",
        async () => {
          throw new TypeError(`fetch failed ${BEARER}`, {
            cause: new Error(`socket hang up ${BEARER}`),
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
          .read({ call: CALL, path: "/api/v1/x", answer: ROWS })
          .catch((error: unknown) => error);

        expect(log.lines()).not.toHaveLength(0);
        const seen = log.seen(outcome);
        for (const marker of NEVER_SHOWN) {
          expect(seen).not.toContain(marker);
        }
      }
    );
  });

  // Argo CD's bytes are the vendor's. Whatever they are, the call returns
  // what the schema allows or fails with an ArgoCdError, and logs none of
  // them.
  const seed = propertySeed();
  it(
    `returns what the schema allows, or an ArgoCdError, for any answer (PROPERTY_SEED=${seed})`,
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
          .read({ call: CALL, path: "/api/v1/x", answer: ROWS })
          .catch((error: unknown) => error);

        if (outcome instanceof ArgoCdError) {
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
