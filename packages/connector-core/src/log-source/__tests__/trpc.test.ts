import { TRPCError } from "@trpc/server";
import { describe, expect, it } from "vitest";

import { ConnectorError } from "../../errors/index.ts";
import { createLogger } from "../../logger.ts";
import { newConnectorRouter, newConnectorTRPC } from "../../trpc.ts";
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
    without: newConnectorRouter("src", t, {}, install, metadata),
    with: newConnectorRouter(
      "src",
      t,
      {},
      install,
      metadata,
      newLogsRouter(t, logs)
    ),
  };
};

const newCaller = (logs: LogSourceHandlers = handlers) => {
  const { t, with: router } = newRouters(logs);
  return t.createCallerFactory(router)({ logger: createLogger() }).src.logs;
};

describe("newConnectorRouter", () => {
  it("mounts logs only when given", () => {
    const routers = newRouters();
    expect(Object.keys(routers.without._def.procedures).sort()).toEqual([
      "src.install.validation",
      "src.metadata.get",
    ]);
    expect(Object.keys(routers.with._def.procedures).sort()).toEqual([
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
