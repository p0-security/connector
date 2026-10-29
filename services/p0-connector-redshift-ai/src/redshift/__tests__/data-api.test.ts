import { ConnectorError, createLogger } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { fakeDataApi, install, provisioned } from "../../__tests__/fakes.ts";
import { newRedshiftSession } from "../data-api.ts";

const logger = createLogger();
const noWait = async () => {};

const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("newRedshiftSession", () => {
  it("names a workgroup, and sends no user or secret", async () => {
    const api = fakeDataApi();
    const session = newRedshiftSession(install, logger, {
      client: api.client,
      wait: noWait,
    });
    await session.execute("SELECT 1");
    expect(api.calls[0]).toEqual({
      command: "ExecuteStatementCommand",
      input: { WorkgroupName: "analytics", Database: "dev", Sql: "SELECT 1" },
    });
  });

  it("names a cluster, in the database asked for", async () => {
    const api = fakeDataApi();
    const session = newRedshiftSession(provisioned, logger, {
      client: api.client,
      wait: noWait,
    });
    await session.execute("SELECT 1", "other");
    expect(api.calls[0]!.input).toEqual({
      ClusterIdentifier: "analytics",
      Database: "other",
      Sql: "SELECT 1",
    });
  });

  it("returns rows keyed by column", async () => {
    const api = fakeDataApi();
    api.on("SELECT usename", () => [
      { usename: "a", usesuper: false, n: 3 },
      { usename: "b", usesuper: true, n: null },
    ]);
    const session = newRedshiftSession(install, logger, {
      client: api.client,
      wait: noWait,
    });
    await expect(session.query("SELECT usename")).resolves.toEqual([
      { usename: "a", usesuper: false, n: 3 },
      { usename: "b", usesuper: true, n: null },
    ]);
  });

  it("reads every page of a result", async () => {
    const pages = [
      {
        ColumnMetadata: [{ name: "x" }],
        Records: [[{ longValue: 1 }]],
        NextToken: "t",
      },
      { Records: [[{ longValue: 2 }]] },
    ];
    const client = {
      send: async (command: { constructor: { name: string } }) => {
        switch (command.constructor.name) {
          case "ExecuteStatementCommand":
            return { Id: "s1" };
          case "DescribeStatementCommand":
            return { Status: "FINISHED", HasResultSet: true };
          default:
            return pages.shift();
        }
      },
    } as never;
    const session = newRedshiftSession(install, logger, {
      client,
      wait: noWait,
    });
    await expect(session.query("SELECT x")).resolves.toEqual([
      { x: 1 },
      { x: 2 },
    ]);
  });

  it("polls until the statement settles", async () => {
    const statuses = ["SUBMITTED", "STARTED", "FINISHED"];
    const waits: number[] = [];
    const client = {
      send: async (command: { constructor: { name: string } }) =>
        command.constructor.name === "ExecuteStatementCommand"
          ? { Id: "s1" }
          : { Status: statuses.shift() },
    } as never;
    const session = newRedshiftSession(install, logger, {
      client,
      wait: async (ms) => {
        waits.push(ms);
      },
    });
    await session.execute("SELECT 1");
    expect(waits).toEqual([100, 250]);
  });

  it("cancels a statement at the deadline", async () => {
    let time = 0;
    const sent: string[] = [];
    const client = {
      send: async (command: { constructor: { name: string } }) => {
        sent.push(command.constructor.name);
        return command.constructor.name === "ExecuteStatementCommand"
          ? { Id: "s1" }
          : { Status: "STARTED" };
      },
    } as never;
    const session = newRedshiftSession(install, logger, {
      client,
      wait: async (ms) => {
        time += ms;
      },
      now: () => time,
    });
    const data = await errorOf(session.execute("SELECT pg_sleep(600)"));
    expect(data.type).toBe("upstream_unavailable");
    expect(sent.at(-1)).toBe("CancelStatementCommand");
  });

  it.each([
    ["ERROR: permission denied for schema hr", "insufficient_privileges"],
    [
      'ERROR: user "x" cannot be dropped because the user owns some object',
      "dependency_violation",
    ],
    ['ERROR: role "x" already exists', "already_exists"],
    ['ERROR: relation "x" does not exist', "object_not_found"],
    ["ERROR: syntax error", "unknown"],
  ])("maps %j to %s", async (error, type) => {
    const api = fakeDataApi();
    api.on("DO", () => ({ error }));
    const session = newRedshiftSession(install, logger, {
      client: api.client,
      wait: noWait,
    });
    const data = await errorOf(session.execute("DO it"));
    expect(data.type).toBe(type);
    expect(data.payload).toEqual({ statement: "DO IT" });
  });

  it("maps an AWS refusal, and keeps the statement's text out of the error", async () => {
    const client = {
      send: async () => {
        throw Object.assign(new Error("not authorized"), {
          name: "AccessDeniedException",
        });
      },
    } as never;
    const session = newRedshiftSession(install, logger, {
      client,
      wait: noWait,
    });
    const data = await errorOf(
      session.execute(`GRANT ROLE "secret_name" TO x`)
    );
    expect(data.type).toBe("insufficient_privileges");
    expect(JSON.stringify(data)).not.toContain("secret_name");
  });

  it("runs a batch as one call", async () => {
    const api = fakeDataApi();
    const session = newRedshiftSession(install, logger, {
      client: api.client,
      wait: noWait,
    });
    await session.batch(["CREATE ROLE a", "GRANT ROLE a TO b"]);
    expect(api.calls[0]).toEqual({
      command: "BatchExecuteStatementCommand",
      input: {
        WorkgroupName: "analytics",
        Database: "dev",
        Sqls: ["CREATE ROLE a", "GRANT ROLE a TO b"],
      },
    });
  });
});
