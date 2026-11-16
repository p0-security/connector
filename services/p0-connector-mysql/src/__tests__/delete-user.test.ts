import { createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { router } from "../accesses/role/handler.ts";
import { t } from "../router.ts";

const P0_USER = "p0_iam_manager";

// The user the fake database reports for CURRENT_USER(). On Cloud SQL this is
// the connector's service account, not `p0User`.
let sessionUser = P0_USER;

const raw = vi.fn(async (sql: string, _bindings?: unknown[]) =>
  sql.includes("CURRENT_USER()") ? [[{ name: sessionUser }]] : [[]]
);

vi.mock("../dbclient.ts", () => ({
  newClient: vi.fn(async () => ({ raw, destroy: async () => {} })),
}));

const client = router(t).createCaller({ logger: createLogger() });

const context = {
  requestId: "test-request-id",
  db: {
    host: "localhost",
    port: 3306,
    p0User: P0_USER,
    cloud: "rds" as const,
  },
};

const dropCalls = () =>
  raw.mock.calls.filter(([sql]) => sql.startsWith("DROP USER"));

describe("MySQL deleteUser connector boundary", () => {
  beforeEach(() => {
    raw.mockClear();
    sessionUser = P0_USER;
  });

  it("refuses to drop the connector's own user", async () => {
    await expect(
      client.deleteUser({ userId: P0_USER, userBody: P0_USER, context })
    ).rejects.toThrow("the connector's own identity");
    expect(dropCalls()).toEqual([]);
  });

  it("refuses to drop the Cloud SQL session user the connector runs as", async () => {
    sessionUser = "p0-connector-sa";
    await expect(
      client.deleteUser({
        userId: "p0-connector-sa",
        userBody: "p0-connector-sa",
        context: { ...context, db: { ...context.db, cloud: "cloudsql" } },
      })
    ).rejects.toThrow("the connector's own identity");
    expect(dropCalls()).toEqual([]);
  });

  it("drops an ordinary P0 user", async () => {
    await client.deleteUser({
      userId: "p0_alice",
      userBody: "p0_alice",
      context,
    });
    expect(dropCalls()).toEqual([["DROP USER IF EXISTS ??", ["p0_alice"]]]);
  });
});
