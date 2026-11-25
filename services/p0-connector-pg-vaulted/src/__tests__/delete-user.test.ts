import { createLogger } from "@p0security/connector-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { router } from "../accesses/role/handler.ts";
import { t } from "../router.ts";

const P0_USER = "p0_iam_manager";

const raw = vi.fn(
  async (
    _sql: string,
    _bindings?: unknown[]
  ): Promise<{ rows: unknown[] }> => ({ rows: [] })
);

type FakeDbArgs = {
  connectorHeldRoles?: string[];
  existingRoles?: string[];
  openSessions?: Record<string, boolean[]>;
  // pids whose sessions exited on their own before the re-check
  exitedPids?: number[];
  terminateFails?: boolean;
};

const fakeDb = (args: FakeDbArgs = {}) => {
  const {
    connectorHeldRoles = [],
    existingRoles = [],
    openSessions = {},
    exitedPids = [],
    terminateFails = false,
  } = args;
  return raw.mockImplementation(async (sql: string, bindings?: unknown[]) => {
    if (sql === "SELECT rolname FROM pg_roles WHERE rolname = ?") {
      const [name] = (bindings ?? []) as [string];
      return { rows: existingRoles.includes(name) ? [{ rolname: name }] : [] };
    }
    if (sql.includes("FROM pg_roles")) {
      const [names] = (bindings ?? []) as [string[]];
      return {
        rows: names
          .filter((name) => connectorHeldRoles.includes(name))
          .map((rolname) => ({ rolname })),
      };
    }
    if (sql.includes("pg_terminate_backend")) {
      if (terminateFails) throw new Error("permission denied");
      const [name] = (bindings ?? []) as [string];
      return {
        rows: (openSessions[name] ?? []).map((ended, pid) => ({
          pid,
          ended,
        })),
      };
    }
    if (sql.includes("WHERE pid = ANY")) {
      const [pids] = (bindings ?? []) as [number[]];
      return {
        rows: pids
          .filter((pid) => !exitedPids.includes(pid))
          .map((pid) => ({ pid })),
      };
    }
    return { rows: [] };
  });
};

vi.mock("../dbclient.ts", () => ({
  newClient: vi.fn(async () => ({ raw, destroy: async () => {} })),
}));

const client = router(t).createCaller({ logger: createLogger() });

const GRANT_ENDS_AT = "2026-12-01T17:30:00-05:00";
const LOGIN_UNTIL = "WITH LOGIN VALID UNTIL '2026-12-01T22:30:00.000Z'";

const context = {
  requestId: "test-request-id",
  grantEndsAt: GRANT_ENDS_AT,
  db: {
    host: "localhost",
    port: 5432,
    p0User: P0_USER,
    managerSecret:
      "p0/install/postgres/vpc-0a1b2c3d4e5f67890/test-target/p0manager",
    database: "postgres",
    cloud: "rds" as const,
  },
};

const sqlCalls = () => raw.mock.calls.map(([sql]) => sql);

const filterDropStatements = () =>
  sqlCalls().filter((sql) => sql.startsWith("DROP ROLE"));

const filterWriteStatements = () =>
  sqlCalls().filter(
    (sql) =>
      /^(CREATE|ALTER|DROP) ROLE/.test(sql) ||
      sql.includes("pg_terminate_backend")
  );

beforeEach(() => {
  raw.mockClear();
  fakeDb();
});

describe("Postgres deleteUser connector boundary", () => {
  it("refuses to drop the connector's own user", async () => {
    await expect(
      client.deleteUser({ userId: P0_USER, userBody: P0_USER, context })
    ).rejects.toThrow("the connector's own identity");
    expect(filterDropStatements()).toEqual([]);
  });

  it("refuses to drop a role the connector inherits", async () => {
    fakeDb({ connectorHeldRoles: ["p0_connector_group"] });
    await expect(
      client.deleteUser({
        userId: "p0_connector_group",
        userBody: "p0_connector_group",
        context,
      })
    ).rejects.toThrow("the connector's own identity");
    expect(filterDropStatements()).toEqual([]);
  });

  it("only drops a user that no longer exists", async () => {
    await client.deleteUser({
      userId: "p0_alice",
      userBody: "p0_alice",
      context,
    });
    expect(filterWriteStatements()).toEqual(['DROP ROLE IF EXISTS "p0_alice"']);
  });

  it("blocks new sign-ins and ends open sessions before it drops the user", async () => {
    fakeDb({
      existingRoles: ["p0_alice"],
      openSessions: { p0_alice: [true, true] },
    });
    await client.deleteUser({
      userId: "p0_alice",
      userBody: "p0_alice",
      context,
    });
    expect(filterWriteStatements()).toEqual([
      'ALTER ROLE "p0_alice" NOLOGIN',
      "SELECT pid, pg_terminate_backend(pid) AS ended FROM pg_stat_activity WHERE usename = ?",
      'DROP ROLE IF EXISTS "p0_alice"',
    ]);
  });

  it("drops the user, then throws, when a session doesn't end", async () => {
    fakeDb({
      existingRoles: ["p0_alice"],
      openSessions: { p0_alice: [true, false] },
    });
    await expect(
      client.deleteUser({ userId: "p0_alice", userBody: "p0_alice", context })
    ).rejects.toThrow("failed to end its open sessions");
    expect(filterDropStatements()).toEqual(['DROP ROLE IF EXISTS "p0_alice"']);
  });

  it("doesn't throw when a session exits on its own before it is ended", async () => {
    fakeDb({
      existingRoles: ["p0_alice"],
      openSessions: { p0_alice: [true, false] },
      exitedPids: [1],
    });
    await client.deleteUser({
      userId: "p0_alice",
      userBody: "p0_alice",
      context,
    });
    expect(filterDropStatements()).toEqual(['DROP ROLE IF EXISTS "p0_alice"']);
  });

  it("drops the user, then throws, when ending sessions fails", async () => {
    fakeDb({ existingRoles: ["p0_alice"], terminateFails: true });
    await expect(
      client.deleteUser({ userId: "p0_alice", userBody: "p0_alice", context })
    ).rejects.toThrow("failed to end its open sessions");
    expect(filterDropStatements()).toEqual(['DROP ROLE IF EXISTS "p0_alice"']);
  });
});

describe("Postgres shared login end", () => {
  it("creates a missing user that can sign in until grantEndsAt", async () => {
    await client.provisionUser({ userBody: "p0_alice", context });
    expect(filterWriteStatements()).toEqual([
      `CREATE ROLE "p0_alice" ${LOGIN_UNTIL}`,
    ]);
  });

  it("moves an existing user's end, turns login back on and keeps the user", async () => {
    fakeDb({ existingRoles: ["p0_alice"] });
    await client.provisionUser({ userBody: "p0_alice", context });
    expect(filterWriteStatements()).toEqual([
      `ALTER ROLE "p0_alice" ${LOGIN_UNTIL}`,
    ]);
  });

  it("returns null and writes nothing for a missing user", async () => {
    await expect(
      client.identifyUser({ userBody: "p0_alice", context })
    ).resolves.toBeNull();
    expect(filterWriteStatements()).toEqual([]);
  });

  it("moves an existing user's end when it identifies the user", async () => {
    fakeDb({ existingRoles: ["p0_alice"] });
    await expect(
      client.identifyUser({ userBody: "p0_alice", context })
    ).resolves.toBe("p0_alice");
    expect(filterWriteStatements()).toEqual([
      `ALTER ROLE "p0_alice" ${LOGIN_UNTIL}`,
    ]);
  });

  it("refuses to move the end of the connector's own user", async () => {
    fakeDb({ existingRoles: [P0_USER] });
    await expect(
      client.provisionUser({ userBody: P0_USER, context })
    ).rejects.toThrow("the connector's own identity");
    expect(filterWriteStatements()).toEqual([]);
  });

  it.each([
    ["is missing", undefined],
    ["is not a timestamp", "tomorrow'; DROP ROLE x; --"],
    ["has no offset", "2026-12-01T17:30:00"],
  ])("refuses a request whose grantEndsAt %s", async (_, grantEndsAt) => {
    fakeDb({ existingRoles: ["p0_alice"] });
    await expect(
      client.provisionUser({
        userBody: "p0_alice",
        // @ts-expect-error -- the request is invalid on purpose
        context: { ...context, grantEndsAt },
      })
    ).rejects.toThrow();
    expect(raw).not.toHaveBeenCalled();
  });
});
