import { createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { router } from "../accesses/role/handler.ts";
import { t } from "../router.ts";

const P0_USER = "p0_iam_manager";

// Roles the fake database reports as held by the connector (itself, the
// session user, or a role it inherits), as `connectorRolesSql` would.
let connectorHeldRoles: string[] = [];

const raw = vi.fn(async (sql: string, bindings?: unknown[]) => {
  if (sql.includes("FROM pg_roles")) {
    const [names] = (bindings ?? []) as [string[]];
    return {
      rows: names
        .filter((name) => connectorHeldRoles.includes(name))
        .map((rolname) => ({ rolname })),
    };
  }
  return { rows: [] };
});

vi.mock("../dbclient.ts", () => ({
  newClient: vi.fn(async () => ({ raw, destroy: async () => {} })),
}));

const client = router(t).createCaller({ logger: createLogger() });

const context = {
  requestId: "test-request-id",
  db: {
    host: "localhost",
    port: 5432,
    p0User: P0_USER,
    database: "postgres",
    cloud: "rds" as const,
  },
};

const dropStatements = () =>
  raw.mock.calls
    .map(([sql]) => sql)
    .filter((sql) => sql.startsWith("DROP ROLE"));

describe("Postgres deleteUser connector boundary", () => {
  beforeEach(() => {
    raw.mockClear();
    connectorHeldRoles = [];
  });

  it("refuses to drop the connector's own user", async () => {
    await expect(
      client.deleteUser({ userId: P0_USER, userBody: P0_USER, context })
    ).rejects.toThrow("the connector's own identity");
    expect(dropStatements()).toEqual([]);
  });

  it("refuses to drop a role the connector inherits", async () => {
    connectorHeldRoles = ["p0_connector_group"];
    await expect(
      client.deleteUser({
        userId: "p0_connector_group",
        userBody: "p0_connector_group",
        context,
      })
    ).rejects.toThrow("the connector's own identity");
    expect(dropStatements()).toEqual([]);
  });

  it("drops an ordinary P0 user", async () => {
    await client.deleteUser({
      userId: "p0_alice",
      userBody: "p0_alice",
      context,
    });
    expect(dropStatements()).toEqual(['DROP ROLE IF EXISTS "p0_alice"']);
  });
});
