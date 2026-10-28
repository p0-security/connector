import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  EMAIL,
  TOKEN,
  connectorError,
  launchDarklyError,
  logger,
} from "../../__tests__/fixtures.ts";
import { LAUNCHDARKLY_ROUTES, newLaunchDarklyApi } from "../api.ts";
import {
  INVOCATION_BUDGET_MS,
  MAX_PAGES,
  PAGE_SIZE,
  newLaunchDarklyClient,
  paged,
  withDeadline,
} from "../client.ts";

const CALL = LAUNCHDARKLY_ROUTES.getMembers;

const api = () =>
  newLaunchDarklyApi({ instance: "commercial", token: TOKEN, logger });

const collect = async <T>(rows: AsyncIterable<T>): Promise<T[]> => {
  const all: T[] = [];
  for await (const row of rows) all.push(row);
  return all;
};

const rows = (n: number) => Array.from({ length: n }, (_, i) => i);

describe("paged", () => {
  it("asks for a page at a time from where the last ended, until the total", async () => {
    const readPage = vi.fn(async ({ offset }: { offset: string }) => ({
      items: rows(Math.min(PAGE_SIZE, 45 - Number(offset))),
      totalCount: 45,
    }));

    await expect(collect(paged(api(), CALL, readPage))).resolves.toHaveLength(
      45
    );
    expect(readPage.mock.calls.map(([page]) => page)).toEqual([
      { limit: "20", offset: "0" },
      { limit: "20", offset: "20" },
      { limit: "20", offset: "40" },
    ]);
  });

  // A server whose cap is below the limit answers every page short.
  it("reads on past a short page while the total says there is more", async () => {
    const readPage = vi.fn(async ({ offset }: { offset: string }) => ({
      items: rows(Math.min(10, 25 - Number(offset))),
      totalCount: 25,
    }));

    await expect(collect(paged(api(), CALL, readPage))).resolves.toHaveLength(
      25
    );
    expect(readPage).toHaveBeenCalledTimes(3);
  });

  it("stops on a short page when the list reports no total", async () => {
    const readPage = vi.fn(async ({ offset }: { offset: string }) => ({
      items: rows(offset === "0" ? PAGE_SIZE : 3),
    }));

    await expect(collect(paged(api(), CALL, readPage))).resolves.toHaveLength(
      PAGE_SIZE + 3
    );
    expect(readPage).toHaveBeenCalledTimes(2);
  });

  it("stops on an empty page, whatever the total says", async () => {
    const readPage = vi.fn(async () => ({ items: [], totalCount: 5 }));

    await expect(collect(paged(api(), CALL, readPage))).resolves.toEqual([]);
    expect(readPage).toHaveBeenCalledTimes(1);
  });

  it("fails on a page longer than it asked for, and logs why", async () => {
    const warn = vi.spyOn(logger, "warn");

    const error = await launchDarklyError(() =>
      collect(paged(api(), CALL, async () => ({ items: rows(PAGE_SIZE + 1) })))
    );

    expect(error.failure).toEqual({
      kind: "unexpected",
      reason: "too_many_rows",
    });
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ route: CALL.route, reason: "too_many_rows" }),
      expect.any(String)
    );
  });

  it("gives up after MAX_PAGES pages that never reach the total", async () => {
    const readPage = vi.fn(async () => ({
      items: rows(PAGE_SIZE),
      totalCount: Number.MAX_SAFE_INTEGER,
    }));

    const error = await launchDarklyError(() =>
      collect(paged(api(), CALL, readPage))
    );

    expect(error.failure).toEqual({ kind: "unexpected", reason: "endless" });
    expect(readPage).toHaveBeenCalledTimes(MAX_PAGES);
  });
});

describe("withDeadline", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /**
   * LaunchDarkly answering every call with a full page of members that
   * never reaches its total, each a second after the call.
   */
  const slowLaunchDarkly = (clock: { now: number }) => {
    const fetch = vi.fn(async () => {
      clock.now += 1000;
      return Response.json({
        items: rows(PAGE_SIZE).map((i) => ({
          _id: `m${i}`,
          _pendingInvite: false,
          _verified: true,
          email: EMAIL,
        })),
        totalCount: Number.MAX_SAFE_INTEGER,
      });
    });
    vi.stubGlobal("fetch", fetch);
    return fetch;
  };

  const listMembers = (bounded: ReturnType<typeof withDeadline>) =>
    bounded.read({
      route: "getMembers",
      query: { filter: `email:${EMAIL}` },
      answer: z.unknown(),
    });

  it("passes calls through until the budget is spent, then refuses them", async () => {
    const clock = { now: 0 };
    const fetch = slowLaunchDarkly(clock);
    const bounded = withDeadline(api(), {
      budgetMs: 3000,
      now: () => clock.now,
    });

    for (let call = 0; call < 3; call++) await listMembers(bounded);
    const { data } = await connectorError(() => listMembers(bounded));

    expect(fetch).toHaveBeenCalledTimes(3);
    expect(data).toMatchObject({
      type: "upstream_unavailable",
      payload: { host: bounded.host, budgetMs: 3000 },
    });
    expect(data.message).toBe(
      `The connector stopped before GET /api/v2/members: it had spent the 3 seconds one request may spend calling LaunchDarkly at ${bounded.host}. LaunchDarkly may be slow, or the account may list more than one request can read. Try again later.`
    );
  });

  it("ends a client's long listing between pages", async () => {
    const clock = { now: 0 };
    const fetch = slowLaunchDarkly(clock);
    const client = newLaunchDarklyClient(api(), { now: () => clock.now });

    const { data } = await connectorError(() =>
      client.listMembersByEmail(EMAIL)
    );

    expect(data.type).toBe("upstream_unavailable");
    expect(fetch).toHaveBeenCalledTimes(INVOCATION_BUDGET_MS / 1000);
  });
});
