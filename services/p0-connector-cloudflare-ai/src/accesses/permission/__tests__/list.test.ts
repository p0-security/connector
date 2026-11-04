import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT_ID,
  INSTALL_INPUT,
  logger,
  stubToken,
} from "../../../__tests__/fixtures.ts";
import {
  failed,
  ok,
  stubCloudflare,
} from "../../../cloudflare/__tests__/fake-cloudflare.ts";
import { CLOUDFLARE_API } from "../../../cloudflare/cloudflare-api.ts";
import { connectorRouter } from "../../../router.ts";
import type * as SecretsModule from "../../../secrets.ts";
import type { GroupScope, ListerQuery } from "../definition.ts";
import { DENIED_GROUPS, UNSUPPORTED_GROUPS } from "../hidden.ts";

// The install token's read is `secrets.ts`'s business. Here it answers with
// the token.
vi.mock("../../../secrets.ts", async (importOriginal) => ({
  ...(await importOriginal<typeof SecretsModule>()),
  readToken: vi.fn(),
}));

const ACCOUNT = `/accounts/${ACCOUNT_ID}`;
const ACCOUNT_SCOPE = "com.cloudflare.api.account";
const ZONE_SCOPE = "com.cloudflare.api.account.zone";

type Group = {
  id: string;
  name: string;
  scopes: string[];
  is_selectable?: boolean;
};

const DNS_READ: Group = {
  id: "dns-read",
  name: "DNS Read",
  scopes: [ZONE_SCOPE],
};
const WORKERS: Group = {
  id: "workers",
  name: "Workers Scripts Write",
  scopes: [ACCOUNT_SCOPE],
};

const stubGroups = (groups: Group[]) =>
  stubCloudflare({
    [`GET ${ACCOUNT}/tokens/permission_groups`]: () => ok(groups),
  });

// Some tests send a query the schema refuses, so it isn't typed.
const list = (query: object) =>
  connectorRouter
    .createCaller({ logger })
    ["cloudflare-ai"].accesses.permission.list({
      query: { context: INSTALL_INPUT, ...query } as ListerQuery,
    });

const listGroups = (scope: GroupScope) => list({ scope, type: "policies" });

stubToken();

describe("list policies", () => {
  it("lists each scope's own groups, by id and name", async () => {
    stubGroups([WORKERS, DNS_READ]);

    expect(await listGroups("account")).toEqual([
      { key: "workers", value: "Workers Scripts Write" },
    ]);
    expect(await listGroups("zone")).toEqual([
      { key: "dns-read", value: "DNS Read" },
    ]);
  });

  const hidden = Object.entries({ ...DENIED_GROUPS, ...UNSUPPORTED_GROUPS });

  it("hides 25 groups by id", () => {
    expect(hidden).toHaveLength(25);
  });

  // Each hidden group is given both scopes, so only its id can hide it.
  it.each(hidden)("hides %s (%s) on both scopes", async (id, name) => {
    stubGroups([
      WORKERS,
      { id, name, scopes: [ACCOUNT_SCOPE] },
      { id, name, scopes: [ZONE_SCOPE] },
      DNS_READ,
    ]);

    expect((await listGroups("account")).map(({ key }) => key)).toEqual([
      "workers",
    ]);
    expect((await listGroups("zone")).map(({ key }) => key)).toEqual([
      "dns-read",
    ]);
  });

  it.each([
    "com.cloudflare.edge.r2.bucket",
    "com.cloudflare.edge.worker.script",
    "com.cloudflare.api.account.flagship.app",
  ])("hides groups on the %s scope", async (scope) => {
    stubGroups([{ id: "other", name: "Other", scopes: [scope] }]);

    expect(await listGroups("account")).toEqual([]);
    expect(await listGroups("zone")).toEqual([]);
  });

  it("hides a group with a resource scope beside the asked one", async () => {
    stubGroups([
      {
        id: "mixed",
        name: "Mixed",
        scopes: [ACCOUNT_SCOPE, "com.cloudflare.edge.r2.bucket"],
      },
    ]);

    expect(await listGroups("account")).toEqual([]);
  });

  it("hides a group with no scope", async () => {
    stubGroups([{ id: "none", name: "None", scopes: [] }]);

    expect(await listGroups("account")).toEqual([]);
    expect(await listGroups("zone")).toEqual([]);
  });

  it("hides a group that isn't selectable", async () => {
    stubGroups([
      { ...WORKERS, is_selectable: false },
      { ...DNS_READ, is_selectable: true },
    ]);

    expect(await listGroups("account")).toEqual([]);
    expect(await listGroups("zone")).toEqual([
      { key: "dns-read", value: "DNS Read" },
    ]);
  });

  it("maps a failed Cloudflare call", async () => {
    stubCloudflare({
      [`GET ${ACCOUNT}/tokens/permission_groups`]: () =>
        failed(403, [{ code: 9109, message: "Unauthorized" }]),
    });

    await expect(listGroups("account")).rejects.toMatchObject({
      data: { type: "insufficient_privileges" },
    });
  });
});

describe("list zone", () => {
  it("lists all zones first, then every zone of the account on every page, by name", async () => {
    const cloudflare = stubCloudflare({
      "GET /zones": (url) =>
        url.searchParams.get("page") === "1"
          ? ok([{ id: "z-1", name: "a.example" }], { page: 1, total_pages: 2 })
          : ok([{ id: "z-2", name: "b.example" }], { page: 2, total_pages: 2 }),
    });

    expect(await list({ type: "zone" })).toEqual([
      { key: "*", value: "All zones" },
      { key: "a.example", value: "a.example" },
      { key: "b.example", value: "b.example" },
    ]);
    expect(cloudflare.calls()).toEqual(
      [1, 2].map(
        (page) =>
          `GET ${CLOUDFLARE_API}/zones?account.id=${ACCOUNT_ID}&page=${page}&per_page=50`
      )
    );
  });

  it("lists only all zones when the account has none", async () => {
    stubCloudflare({ "GET /zones": () => ok([], { page: 1, total_pages: 0 }) });

    expect(await list({ type: "zone" })).toEqual([
      { key: "*", value: "All zones" },
    ]);
  });
});

describe("list query", () => {
  it.each([
    { type: "permission" },
    { type: "policies" },
    { scope: "all-zones", type: "policies" },
  ])("refuses %o", async (query) => {
    const cloudflare = stubCloudflare({});

    await expect(list(query)).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(cloudflare.fetch).not.toHaveBeenCalled();
  });
});
