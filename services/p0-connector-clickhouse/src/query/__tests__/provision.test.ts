import { ConnectorError } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeCloud,
  failing,
  fakeEndpoint,
  isCall,
  newSeededCloud,
} from "../../__tests__/fake-cloud.ts";
import {
  CREDENTIALS,
  KEY_ID,
  KEY_SECRET,
  KEY_UUID,
  SERVICE_ID,
} from "../../__tests__/fixtures.ts";
import { connectorError, newRecordingLogger } from "../../__tests__/helpers.ts";
import { newCloudClient } from "../../cloud/client.ts";
import {
  type P0EndpointName,
  P0_ENDPOINTS,
  P0_ENDPOINT_NAMES,
} from "../endpoints.ts";
import { provisionEndpoint } from "../provision.ts";

// `vi.hoisted` guarantees this exists before the (hoisted) `vi.mock` factory runs.
const readApiKey = vi.hoisted(() => vi.fn());
vi.mock("../../secrets.ts", () => ({ readApiKey }));

const OLD_KEY = "0a9b8c7d-6e5f-4a3b-9c2d-1e0f9a8b7c6d";
const ENDPOINTS_PATH = /\/query-api-endpoints/;
const ONE_ENDPOINT = /\/query-api-endpoints\/[^/]+$/;
const SERVICE_PATH = `/v1/organizations/${CREDENTIALS.organizationId}/services/${SERVICE_ID}`;

let cloud: FakeCloud;
let logs: ReturnType<typeof newRecordingLogger>;

const provision = (name: P0EndpointName = "p0_objects") =>
  provisionEndpoint({
    cloud: newCloudClient({ ...CREDENTIALS, log: logs.log }),
    serviceId: SERVICE_ID,
    apiKeyUuid: KEY_UUID,
    name,
    log: logs.log,
  });

/** One of P0's endpoints, as P0 leaves it for the key. */
const p0Endpoint = (
  name: P0EndpointName,
  overrides: Parameters<typeof fakeEndpoint>[0] | object = {}
) =>
  fakeEndpoint({
    name,
    sql: P0_ENDPOINTS[name].sql,
    apiKeyIds: [KEY_UUID],
    ...overrides,
  });

const seedAll = () => {
  for (const name of P0_ENDPOINT_NAMES) {
    cloud.endpointsOf(SERVICE_ID).push(p0Endpoint(name));
  }
};

const held = () => cloud.endpointsOf(SERVICE_ID);
const byName = (name: string) => held().filter((e) => e.name === name);
const reads = () => cloud.calls.filter(isCall("GET", ONE_ENDPOINT));

beforeEach(() => {
  cloud = newSeededCloud();
  vi.stubGlobal("fetch", cloud.fetch);
  logs = newRecordingLogger();
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

describe("provisionEndpoint", () => {
  it("creates the endpoint on a service that has none, and returns it", async () => {
    const endpoint = await provision("p0_objects");

    expect(held().map(({ name }) => name)).toEqual(["p0_objects"]);
    const [objects] = byName("p0_objects");
    expect(objects).toMatchObject({
      sql: P0_ENDPOINTS.p0_objects.sql,
      database: "system",
      parameters: {},
      apiKeyIds: [KEY_UUID],
      roles: ["sql_console_read_only"],
      allowedOrigins: [],
    });
    expect(endpoint).toEqual({
      id: objects?.id,
      name: "p0_objects",
      url: objects?.url,
    });
    expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);
    expect(reads()).toEqual([]);
  });

  it("lists once and reads the endpoint when it's current, changing nothing", async () => {
    seedAll();

    await provision("p0_objects");

    expect(cloud.writes()).toEqual([]);
    expect(
      cloud.calls.filter(isCall("GET", /query-api-endpoints$/))
    ).toHaveLength(1);
    const [objects] = byName("p0_objects");
    expect(reads().map(({ path }) => path.split("/").pop())).toEqual([
      objects?.id,
    ]);
    expect(cloud.calls).toHaveLength(2);
  });

  it.each([
    ["its SQL changed", { sql: "SELECT 2" }],
    ["its parameters changed", { parameters: { database: "x" } }],
    ["its role changed", { roles: ["sql_console_admin"] }],
    [
      "another role added",
      { roles: ["sql_console_read_only", "sql_console_admin"] },
    ],
    ["its database changed", { database: "default" }],
    ["a CORS origin added", { allowedOrigins: ["https://example.com"] }],
    ["the old key's ID, after a rotation", { apiKeyIds: [OLD_KEY] }],
    ["another key added", { apiKeyIds: [KEY_UUID, OLD_KEY] }],
  ])(
    "puts the definition back on the endpoint with %s",
    async (_case, drift) => {
      seedAll();
      const [objects] = byName("p0_objects");
      Object.assign(objects ?? {}, drift);

      await provision("p0_objects");

      expect(cloud.writes()).toEqual([
        {
          method: "PUT",
          path: `${SERVICE_PATH}/query-api-endpoints/${objects?.id}`,
          body: {
            name: "p0_objects",
            sql: P0_ENDPOINTS.p0_objects.sql,
            database: "system",
            parameters: {},
            apiKeyIds: [KEY_UUID],
            roles: ["sql_console_read_only"],
            allowedOrigins: [],
          },
        },
      ]);
      expect(byName("p0_objects")[0]).toMatchObject({
        sql: P0_ENDPOINTS.p0_objects.sql,
        apiKeyIds: [KEY_UUID],
        roles: ["sql_console_read_only"],
        allowedOrigins: [],
      });
    }
  );

  // A drift the listing shows needs no read: the update puts all of it back.
  it("puts back a drift the listing shows without reading the endpoint", async () => {
    seedAll();
    Object.assign(byName("p0_objects")[0] ?? {}, { apiKeyIds: [OLD_KEY] });

    await provision("p0_objects");

    expect(cloud.writes().map(({ method }) => method)).toEqual(["PUT"]);
    expect(reads()).toEqual([]);
  });

  it("creates the endpoint when it's gone between the listing and the read", async () => {
    seedAll();
    cloud.intercept((call) =>
      isCall("GET", ONE_ENDPOINT)(call) ? failing(404) : undefined
    );

    const endpoint = await provision("p0_objects");

    expect(cloud.writes().map(({ method }) => method)).toEqual(["POST"]);
    expect(endpoint.name).toBe("p0_objects");
  });

  it("deletes another P0-made endpoint with the same name, keeping the first", async () => {
    seedAll();
    const [first] = byName("p0_objects");
    held().push(p0Endpoint("p0_objects"));

    await provision();

    expect(byName("p0_objects").map(({ id }) => id)).toEqual([first?.id]);
  });

  it("logs a duplicate it can't delete, and carries on", async () => {
    seedAll();
    const duplicate = p0Endpoint("p0_objects");
    held().push(duplicate);
    cloud.intercept((call) =>
      isCall("DELETE", ENDPOINTS_PATH)(call) ? failing(500) : undefined
    );

    await expect(provision()).resolves.toMatchObject({ name: "p0_objects" });

    expect(logs.warn).toHaveBeenCalledWith(
      expect.objectContaining({ endpoint: "p0_objects" }),
      "couldn't delete a stale P0 endpoint"
    );
    expect(held()).toContain(duplicate);
  });

  // What a create or update answers with is what ClickHouse Cloud stored.
  const storedAs = (method: string, name: string, sql: string) =>
    cloud.intercept((call) =>
      isCall(method, ENDPOINTS_PATH)(call) &&
      (call.body as { name?: string } | undefined)?.name === name
        ? {
            status: 200,
            body: {
              status: 200,
              result: p0Endpoint(name as P0EndpointName, { sql }),
            },
          }
        : undefined
    );

  it.each(["POST", "PUT"])(
    "won't hand back the endpoint when ClickHouse Cloud stored other than the %s sent",
    async (method) => {
      if (method === "PUT") {
        seedAll();
        Object.assign(byName("p0_objects")[0] ?? {}, { apiKeyIds: [OLD_KEY] });
      }
      storedAs(method, "p0_objects", "SELECT 2");

      expect(await connectorError(() => provision())).toEqual({
        type: "unknown",
        message: `ClickHouse Cloud stored P0's Query API endpoint p0_objects on service ${SERVICE_ID} other than as P0 sent it, so P0 won't run it.`,
        payload: { serviceId: SERVICE_ID, endpoint: "p0_objects" },
      });
    }
  );

  it("never reads, changes or deletes an endpoint that isn't P0's", async () => {
    const foreign = [
      fakeEndpoint({ name: "dashboard_users", apiKeyIds: [OLD_KEY] }),
      fakeEndpoint({ name: "P0_objects" }),
      fakeEndpoint({ name: "p0objects" }),
      fakeEndpoint({ name: "xp0_objects", roles: ["sql_console_admin"] }),
    ];
    held().push(...foreign);

    await provision();

    const touched = cloud.calls.filter((call) =>
      foreign.some(({ id }) => call.path.endsWith(id))
    );
    expect(touched).toEqual([]);
    expect(held().slice(0, foreign.length)).toEqual(foreign);
  });

  it("reads every page of the listing", async () => {
    cloud = newSeededCloud({ pageSize: 2 });
    vi.stubGlobal("fetch", cloud.fetch);
    for (let n = 0; n < 6; n++) {
      held().push(fakeEndpoint({ name: `other_${n}` }));
    }
    seedAll();

    await provision();

    expect(cloud.writes()).toEqual([]);
    const pages = cloud.calls.filter(isCall("GET", /query-api-endpoints$/));
    expect(pages.map(({ query }) => query.cursor)).toEqual([
      undefined,
      "2",
      "4",
      "6",
    ]);
  });

  it.each(["POST", "PUT"])(
    "names the manage permission when the key may not %s an endpoint",
    async (method) => {
      if (method === "PUT") {
        seedAll();
        Object.assign(byName("p0_objects")[0] ?? {}, { apiKeyIds: [OLD_KEY] });
      }
      cloud.state.permissions.delete(
        "control-plane:service:manage-query-api-endpoints"
      );

      expect(await connectorError(() => provision())).toEqual({
        type: "insufficient_privileges",
        message: `P0's API key can't set up P0's Query API endpoints on ClickHouse Cloud service ${SERVICE_ID}: its p0-connector role lacks control-plane:service:manage-query-api-endpoints. Add the permission to the role, then try again.`,
        payload: { serviceId: SERVICE_ID },
      });
    }
  );

  it("throws any other failed create as it is", async () => {
    cloud.intercept((call) =>
      isCall("POST", ENDPOINTS_PATH)(call) ? failing(502) : undefined
    );

    const error = await provision().catch((e: unknown) => e);

    expect(error).not.toBeInstanceOf(ConnectorError);
    expect(error).toMatchObject({
      name: "ClickHouseError",
      status: 502,
      method: "POST",
    });
  });
});
