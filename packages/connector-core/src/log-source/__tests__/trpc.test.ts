import { TRPCError } from "@trpc/server";
import { describe, expect, expectTypeOf, it } from "vitest";

import { ConnectorError } from "../../errors/index.ts";
import { createLogger } from "../../logger.ts";
import type { AnyConnectorTRPCInstance } from "../../security-perimeters/common/trpc.ts";
import type { ResourceHierarchySchema } from "../../security-perimeters/resource-hierarchy/schema.ts";
import type { ResourceHierarchyRouter } from "../../security-perimeters/resource-hierarchy/trpc.ts";
import {
  type ConnectorRouter,
  newConnectorRouter,
  newConnectorTRPC,
  newTRPCConnectorClient,
} from "../../trpc.ts";
import type { LogQuery, LogReadResult } from "../schema.ts";
import { type LogSourceHandlers, newLogsRouter } from "../trpc.ts";

const query: LogQuery = {
  source: "gcp-audit",
  window: { start: "2026-11-01T10:00:00Z", end: "2026-11-01T12:00:00Z" },
  projectId: "my-project",
  principalEmail: "alice@example.com",
};

const done: LogReadResult = { entries: [], state: "done", gaps: [] };

const handlers: LogSourceHandlers = {
  read: async () => done,
  check: async () => ({ gaps: [] }),
};

const newRouters = (logs: LogSourceHandlers = handlers) => {
  const t = newConnectorTRPC();
  const install = t.router({ validation: t.procedure.query(() => "ok") });
  const metadata = t.router({ get: t.procedure.query(() => "meta") });
  return {
    t,
    resourceIntegration: newConnectorRouter("src", t, {
      accesses: {},
      install,
      metadata,
    }),
    accessLogs: newConnectorRouter("src", t, {
      logs: newLogsRouter(t, logs),
      install,
      metadata,
    }),
  };
};

const newCaller = (logs: LogSourceHandlers = handlers) => {
  const { t, accessLogs: router } = newRouters(logs);
  return t.createCallerFactory(router)({ logger: createLogger() }).src.logs;
};

describe("ConnectorRouter", () => {
  it("keeps accesses on a client typed with access routers", () => {
    type Router = ConnectorRouter<
      "src",
      AnyConnectorTRPCInstance,
      { role: ResourceHierarchyRouter<ResourceHierarchySchema> }
    >;
    const client = newTRPCConnectorClient<Router>({ links: [] });
    expectTypeOf(client.src).toHaveProperty("accesses");
    expectTypeOf(client.src.accesses).toHaveProperty("role");
  });

  it("stands for either kind of connector without access routers", () => {
    const client = newTRPCConnectorClient<ConnectorRouter<"src">>({
      links: [],
    });
    expectTypeOf(client.src).toHaveProperty("metadata");
  });
});

describe("newConnectorRouter", () => {
  it("mounts logs for an access logs connector, and not otherwise", () => {
    const routers = newRouters();
    expect(
      Object.keys(routers.resourceIntegration._def.procedures).sort()
    ).toEqual(["src.install.validation", "src.metadata.get"]);
    expect(Object.keys(routers.accessLogs._def.procedures).sort()).toEqual([
      "src.install.validation",
      "src.logs.check",
      "src.logs.read",
      "src.metadata.get",
    ]);
  });
});

describe("newLogsRouter", () => {
  it("passes the parsed input to the handler and returns its result", async () => {
    const seen: unknown[] = [];
    const caller = newCaller({
      ...handlers,
      read: async (input) => {
        seen.push(input);
        return done;
      },
    });
    await expect(caller.read({ query, cursor: "c" })).resolves.toEqual(done);
    expect(seen).toEqual([{ query, cursor: "c" }]);
  });

  it("rejects a query outside the union with validation_error", async () => {
    const caller = newCaller();
    const error = await caller
      .read({ query: { ...query, source: "azure" } as unknown as LogQuery })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ConnectorError);
    expect((error as ConnectorError).data.type).toBe("validation_error");

    const checkError = await caller
      .check({ target: { ...query, extra: 1 } as unknown as LogQuery })
      .catch((e: unknown) => e);
    expect((checkError as ConnectorError).data.type).toBe("validation_error");
  });

  it("validates the handler's output", async () => {
    const caller = newCaller({
      ...handlers,
      read: async () => ({ ...done, state: "more" }),
    });
    const error = await caller.read({ query }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TRPCError);
    expect((error as TRPCError).code).toBe("INTERNAL_SERVER_ERROR");
  });
});
