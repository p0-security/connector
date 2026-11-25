import { createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TARGET_ID, target } from "../../__tests__/fixtures.ts";
import { newClient } from "../../dbclient.ts";
import { t } from "../../router.ts";
import { router as roleRouter } from "../role/handler.ts";
import { router as sqlRouter } from "../sql/handler.ts";

// No live DB: a call whose input parses stops when it tries to connect.
vi.mock("../../dbclient.ts", () => ({
  newClient: vi.fn(async () => {
    throw new Error("db reached");
  }),
}));

const RDS_SECRET =
  "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!db-0a1b2c3d-4e5f-6789-abcd-ef0123456789-AbC123";

const db = {
  host: target.host,
  port: target.port,
  database: target.database,
  p0User: "p0_iam_manager",
  managerSecret: target.managerSecret,
  targetId: TARGET_ID,
  cloud: "rds" as const,
};

describe.each([
  ["role", roleRouter],
  ["sql", sqlRouter],
])("the %s access's target binding", (_, router) => {
  const client = router(t).createCaller({ logger: createLogger() });

  const provision = (overrides: Partial<typeof db>) =>
    client.provisionUser({
      userBody: "p0_alice",
      context: { requestId: "r123", db: { ...db, ...overrides } },
    });

  const listDatabases = (overrides: Partial<typeof db>) =>
    client.list({
      query: { type: "database", context: { ...db, ...overrides } },
    });

  beforeEach(() => {
    vi.mocked(newClient).mockClear();
  });

  it("signs in with a manager secret P0 names under the request's target", async () => {
    await expect(provision({})).rejects.toThrow("db reached");
  });

  it("signs in with a secret RDS manages, which names no target", async () => {
    await expect(
      provision({ managerSecret: RDS_SECRET, targetId: "billing-prod" })
    ).rejects.toThrow("db reached");
  });

  it.each(["billing-prod", "Orders-prod", "orders-prod2", "orders"])(
    "refuses the fixture's manager secret for target %j, and never signs in",
    async (targetId) => {
      await expect(provision({ targetId })).rejects.toThrow(
        "managerSecret must be a secret of the target targetId"
      );
      await expect(listDatabases({ targetId })).rejects.toThrow(
        "managerSecret must be a secret of the target targetId"
      );
      expect(newClient).not.toHaveBeenCalled();
    }
  );

  it.each(["", "-orders", "orders_prod", "a".repeat(64)])(
    "refuses the target id %j",
    async (targetId) => {
      await expect(provision({ targetId })).rejects.toThrow("targetId");
      expect(newClient).not.toHaveBeenCalled();
    }
  );
});
