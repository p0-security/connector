import type * as Sts from "@aws-sdk/client-sts";
import type * as Connector from "@p0security/connector-core";
import { expect, it, vi } from "vitest";

/** What importing an entry point loaded. */
const loaded = vi.hoisted(() => ({ sts: false, handler: false }));

vi.mock("@aws-sdk/client-sts", async (importOriginal) => {
  loaded.sts = true;
  return await importOriginal<typeof Sts>();
});

vi.mock("@p0security/connector-core", async (importOriginal) => {
  const actual = await importOriginal<typeof Connector>();
  return {
    ...actual,
    newCloudFunction: (...args: Parameters<typeof actual.newCloudFunction>) => {
      loaded.handler = true;
      return actual.newCloudFunction(...args);
    },
  };
});

// Each mock's factory runs once per file, the first time its module loads,
// so the probes only work once: one test, and no retry, which would pass
// with the flags still false.
it(
  "./connector serves the contract without creating the handler or loading client-sts",
  { retry: 0 },
  async () => {
    const contract = await import("../connector.ts");
    expect(contract.DatabricksAiConnectorSpec).toBeDefined();
    expect(loaded).toEqual({ sts: false, handler: false });

    // The root entry serves the same contract beside the handler, and the
    // probes see it load both.
    const root = await import("../index.ts");
    expect(loaded).toEqual({ sts: true, handler: true });
    for (const [name, value] of Object.entries(contract)) {
      expect(root[name as keyof typeof root]).toBe(value);
    }
  }
);
