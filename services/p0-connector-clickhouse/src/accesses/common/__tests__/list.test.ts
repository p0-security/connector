import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  failing,
  isCall,
  newSeededCloud,
  provisionP0Endpoints,
} from "../../../__tests__/fake-cloud.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  EMAIL,
  KEY_ID,
  KEY_SECRET,
  OTHER_SERVICE_ID,
  SERVICE_ID,
} from "../../../__tests__/fixtures.ts";
import {
  connectorError,
  newRecordingLogger,
} from "../../../__tests__/helpers.ts";
import { forgetKeyUuids } from "../../../cloud/client.ts";
import {
  MAX_OBJECTS,
  MAX_OBJECT_BYTES,
  P0_ENDPOINTS,
  P0_ENDPOINT_NAMES,
} from "../../../query/endpoints.ts";
import type { ListerQuery } from "../definition.ts";
import { list } from "../list.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../../secrets.ts", () => ({ readApiKey }));

// Read when the first email is checked, as a deployment's is.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);

let cloud: FakeCloud;
let logs: ReturnType<typeof newRecordingLogger>;

const run = (query: ListerQuery) => list(logs.log, query);

const inService = { context: CREDENTIALS, serviceId: SERVICE_ID };

const SERVICE = /\/services\/[^/]+$/;
const ENDPOINTS = /\/query-api-endpoints$/;

beforeEach(() => {
  cloud = newSeededCloud();
  vi.stubGlobal("fetch", cloud.fetch);
  logs = newRecordingLogger();
  forgetKeyUuids();
  readApiKey.mockReset();
  readApiKey.mockResolvedValue({
    keyId: KEY_ID,
    keySecret: KEY_SECRET,
    version: "1",
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("member", () => {
  const member = (email: string) =>
    run({ type: "member", context: CREDENTIALS, email });

  it("is [] when no member has the email", async () => {
    cloud.members.push({ userId: "u-bob", email: "bob@acme.com", name: "Bob" });
    expect(await member(EMAIL)).toEqual([]);
  });

  it("finds the member, ignoring case", async () => {
    cloud.members.push(
      { userId: "u-bob", email: "bob@acme.com", name: "Bob" },
      { userId: "u-alice", email: "Alice@Acme.com", name: "Alice" }
    );
    expect(await member(EMAIL)).toEqual([
      { key: "u-alice", value: "Alice@Acme.com" },
    ]);
  });

  it("refuses an email more than one member has", async () => {
    cloud.members.push(
      { userId: "u-1", email: EMAIL, name: "Alice" },
      { userId: "u-2", email: EMAIL.toUpperCase(), name: "Alice" }
    );
    expect(await connectorError(() => member(EMAIL))).toEqual({
      type: "validation_error",
      message: `2 members of the ClickHouse Cloud organization ${CREDENTIALS.organizationId} have the email ${EMAIL}, so P0 can't tell which is the requestor. Ask a ClickHouse Cloud admin to remove the extra member.`,
      payload: { reason: "ambiguous_member", email: EMAIL, members: 2 },
    });
  });

  it("refuses an email whose domain isn't allowed, before any call", async () => {
    expect(
      await connectorError(() => member("mallory@evil.com"))
    ).toMatchObject({
      type: "validation_error",
      payload: { reason: "domain_not_allowed" },
    });
    expect(cloud.calls).toEqual([]);
  });
});

describe("services", () => {
  it("lists every service by ID and name", async () => {
    cloud.services.push({
      id: OTHER_SERVICE_ID,
      name: "staging",
      state: "idle",
      byocId: "byoc-1",
    });
    expect(await run({ type: "services", context: CREDENTIALS })).toEqual([
      { key: SERVICE_ID, value: "prod" },
      { key: OTHER_SERVICE_ID, value: "staging" },
    ]);
  });
});

describe("service", () => {
  const service = (serviceId = SERVICE_ID) =>
    run({ type: "service", context: CREDENTIALS, serviceId });

  it("is [] when the service isn't there", async () => {
    expect(await service(OTHER_SERVICE_ID)).toEqual([]);
  });

  it("is the service's fields, reading none of its endpoints", async () => {
    provisionP0Endpoints(cloud);
    expect(await service()).toEqual([
      { key: "id", value: SERVICE_ID },
      { key: "name", value: "prod" },
      { key: "version", value: "26.4.1.1234" },
      { key: "byoc", value: "false" },
    ]);
    expect(cloud.calls.filter(isCall("GET", ENDPOINTS))).toEqual([]);
    expect(cloud.writes()).toEqual([]);
  });

  it("says when the service is BYOC", async () => {
    cloud.services[0] = {
      id: SERVICE_ID,
      name: "byoc",
      state: "running",
      byocId: "byoc-1",
    };
    expect(await service()).toEqual([
      { key: "id", value: SERVICE_ID },
      { key: "name", value: "byoc" },
      { key: "version", value: "" },
      { key: "byoc", value: "true" },
    ]);
  });

  it("fails as Cloud fails, other than a missing service", async () => {
    cloud.intercept((call) =>
      isCall("GET", SERVICE)(call) ? failing(403) : undefined
    );
    expect(await connectorError(() => service())).toMatchObject({
      type: "insufficient_privileges",
    });
  });
});

describe("objects", () => {
  const objects = () => run({ type: "objects", ...inService });

  it("lists each object with its kind, keyed db or db.name", async () => {
    provisionP0Endpoints(cloud);
    cloud.rows.set("p0_objects", [
      { database: "analytics", name: "", kind: "database" },
      { database: "analytics", name: "events", kind: "table" },
      { database: "analytics", name: "v_users", kind: "view" },
      { database: "analytics", name: "mv_daily", kind: "materialized-view" },
      { database: "analytics", name: "country_names", kind: "dictionary" },
      { database: "analytics", name: "odd name", kind: "table" },
    ]);
    expect(await objects()).toEqual([
      { key: "analytics", value: "analytics", group: "database" },
      { key: "analytics.events", value: "analytics.events", group: "table" },
      { key: "analytics.v_users", value: "analytics.v_users", group: "view" },
      {
        key: "analytics.mv_daily",
        value: "analytics.mv_daily",
        group: "materialized-view",
      },
      {
        key: "analytics.country_names",
        value: "analytics.country_names",
        group: "dictionary",
      },
      {
        key: "analytics.odd name",
        value: "analytics.odd name",
        group: "table",
      },
    ]);
    // P0's own endpoint, run with no variables.
    const [only] = cloud.runs();
    expect(only?.body).toEqual({ format: "JSONEachRow", queryVariables: {} });
  });

  it("leaves out ClickHouse's own databases and hidden tables in its fixed SQL", () => {
    const { sql } = P0_ENDPOINTS.p0_objects;
    expect(sql).toContain(
      "database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') AND position(database, '.') = 0"
    );
    expect(sql).toContain("NOT is_temporary AND engine != 'Dictionary'");
    expect(sql).toContain(
      "NOT startsWith(name, '.inner.') AND NOT startsWith(name, '.inner_id.')"
    );
    // Renamed in a subquery, where `'' AS name` can't stand for it.
    expect(sql).toContain(
      "FROM (SELECT name AS database FROM system.databases)"
    );
    expect(sql).toContain(`LIMIT ${MAX_OBJECTS + 1}`);
  });

  it(`refuses more than ${MAX_OBJECTS} objects rather than truncate`, async () => {
    provisionP0Endpoints(cloud);
    cloud.rows.set(
      "p0_objects",
      Array.from({ length: MAX_OBJECTS + 1 }, (_, i) => ({
        database: "d",
        name: `t${i}`,
        kind: "table",
      }))
    );
    expect(await connectorError(objects)).toEqual({
      type: "validation_error",
      message:
        "This ClickHouse Cloud service has more than 50,000 databases, tables, views and dictionaries, so P0 can't list them. Request the whole service as '*' instead: that doesn't need the list.",
      payload: { serviceId: SERVICE_ID },
    });
  });

  const LAMBDA_LIMIT = 6 * 1024 * 1024;
  const tooLarge = {
    type: "validation_error",
    message:
      "This ClickHouse Cloud service has too many databases, tables, views and dictionaries to fit in 4 MB, so P0 can't list them. Request the whole service as '*' instead: that doesn't need the list.",
    payload: { serviceId: SERVICE_ID },
  };

  describe("at ClickHouse's 255-byte name limit", () => {
    const longNames = (count: number) =>
      Array.from({ length: count }, (_, i) => ({
        database: "d".repeat(255),
        name: `${i}`.padStart(255, "t"),
        kind: "table",
      }));
    // `{"key":"<255>.<255>","value":"<255>.<255>","group":"table"}` and a comma.
    const ITEM_BYTES = 7 + 513 + 9 + 513 + 17 + 1;
    const FITTING = Math.floor(MAX_OBJECT_BYTES / ITEM_BYTES);

    it("answers with what fits, well under a Lambda's 6 MB", async () => {
      provisionP0Endpoints(cloud);
      cloud.rows.set("p0_objects", longNames(FITTING));

      const answer = await objects();

      expect(answer).toHaveLength(FITTING);
      expect(Buffer.byteLength(JSON.stringify(answer))).toBeLessThanOrEqual(
        MAX_OBJECT_BYTES
      );
    });

    it("refuses one item more, while that answer would still be under 6 MB", async () => {
      provisionP0Endpoints(cloud);
      cloud.rows.set("p0_objects", longNames(FITTING + 1));

      expect(await connectorError(objects)).toEqual(tooLarge);
      // The answer refused, as it would have been serialized: the refusal
      // comes well before Lambda's limit.
      const refused = longNames(FITTING + 1).map(({ database, name }) => ({
        key: `${database}.${name}`,
        value: `${database}.${name}`,
        group: "table",
      }));
      const refusedBytes = Buffer.byteLength(JSON.stringify(refused));
      expect(refusedBytes).toBeGreaterThan(MAX_OBJECT_BYTES);
      expect(refusedBytes).toBeLessThan(LAMBDA_LIMIT - 1024 * 1024);
    });
  });

  it(`refuses ${MAX_OBJECTS} materialized views with 39-byte names, whose answer would pass 6 MB`, async () => {
    provisionP0Endpoints(cloud);
    const rows = Array.from({ length: MAX_OBJECTS }, (_, i) => ({
      database: "d",
      name: `${i}`.padStart(37, "m"),
      kind: "materialized-view",
    }));
    cloud.rows.set("p0_objects", rows);

    expect(await connectorError(objects)).toEqual(tooLarge);
    const answer = rows.map(({ database, name, kind }) => ({
      key: `${database}.${name}`,
      value: `${database}.${name}`,
      group: kind,
    }));
    expect(Buffer.byteLength(JSON.stringify(answer))).toBeGreaterThan(
      LAMBDA_LIMIT
    );
  });

  it("fails as unknown on rows it can't read, without quoting them", async () => {
    provisionP0Endpoints(cloud);
    cloud.rows.set("p0_objects", [
      { database: "a", name: "secret", kind: "x" },
    ]);
    const error = await connectorError(objects);
    expect(error).toMatchObject({ type: "unknown" });
    expect(JSON.stringify(error)).not.toContain("secret");
    expect(JSON.stringify(logs.warn.mock.calls)).not.toContain("secret");
  });

  it("sets up p0_objects on a service that has none, then runs it, in 4 calls", async () => {
    expect(await objects()).toEqual([]);
    expect(
      cloud
        .endpointsOf(SERVICE_ID)
        .map(({ name }) => name)
        .sort()
    ).toEqual([...P0_ENDPOINT_NAMES].sort());
    expect(cloud.runs().map(({ url }) => url)).toEqual([
      cloud.endpointsOf(SERVICE_ID).find(({ name }) => name === "p0_objects")
        ?.url,
    ]);
    // The keys, the endpoint listing, the POST, and the run.
    expect(cloud.calls).toHaveLength(4);
  });

  it("makes 3 calls on a service it already set up", async () => {
    await objects();
    const before = cloud.calls.length;

    await objects();

    // The listing, p0_objects read whole, and its run.
    expect(cloud.calls.length - before).toBe(3);
    expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);
  });

  it("puts p0_objects back when its SQL changed behind P0's back, before running it", async () => {
    const endpoints = provisionP0Endpoints(cloud);
    if (endpoints.p0_objects) {
      endpoints.p0_objects.sql = "SELECT 'system' AS database, '' AS name";
    }

    await objects();

    expect(cloud.writes()).toEqual([
      expect.objectContaining({
        method: "PUT",
        body: expect.objectContaining({ sql: P0_ENDPOINTS.p0_objects.sql }),
      }),
    ]);
    expect(cloud.runs()).toHaveLength(1);
  });

  it("sets the endpoint up again after a 404, and runs it once more", async () => {
    provisionP0Endpoints(cloud);
    let first = true;
    cloud.intercept((call) => {
      if (call.host !== "queries.clickhouse.cloud" || !first) return undefined;
      first = false;
      return { status: 404, body: "gone" };
    });
    expect(await objects()).toEqual([]);
    expect(cloud.calls.filter(isCall("GET", ENDPOINTS))).toHaveLength(2);
    expect(cloud.runs()).toHaveLength(2);
  });

  it("fails on a second 404", async () => {
    provisionP0Endpoints(cloud);
    cloud.intercept((call) =>
      call.host === "queries.clickhouse.cloud"
        ? { status: 404, body: "gone" }
        : undefined
    );
    expect(await connectorError(objects)).toMatchObject({
      type: "object_not_found",
    });
    expect(cloud.runs()).toHaveLength(2);
  });

  it("finds the endpoint again when its ID is gone, as after it was recreated", async () => {
    provisionP0Endpoints(cloud);
    await objects();
    cloud.endpointsOf(SERVICE_ID).length = 0;
    provisionP0Endpoints(cloud);
    expect(await objects()).toEqual([]);
    expect(cloud.calls.filter(isCall("GET", ENDPOINTS))).toHaveLength(2);
    expect(cloud.runs()).toHaveLength(2);
  });
});

describe("every query", () => {
  it("is checked again, since the framework doesn't", async () => {
    await expect(
      run({ type: "objects", context: CREDENTIALS, serviceId: "../keys" })
    ).rejects.toThrow();
    await expect(
      run({ type: "nope", context: CREDENTIALS } as unknown as ListerQuery)
    ).rejects.toThrow();
    expect(cloud.calls).toEqual([]);
  });
});
