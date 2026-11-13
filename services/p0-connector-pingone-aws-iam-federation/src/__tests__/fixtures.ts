import { ConnectorError, createLogger } from "@p0security/connector-core";
import { vi } from "vitest";

export const AWS_SECRET = {
  manager: "aws" as const,
  region: "us-west-2",
  secretId: "pingone-worker-app-secret",
};

export const CLIENT_SECRET = "s3cr3t~worker.app_Secret-value";

export const ENVIRONMENT_ID = "fd5b21b0-d522-48d6-a8e3-8fc197d7b6bc";

export const APP_ID = "2c8a5d6e-1f3b-4a7c-9e0d-5b6a7c8d9e0f";

export const CLIENT_ID = "8b1e4f2a-3c5d-4e6f-a7b8-c9d0e1f2a3b4";

export const APP_INPUT = {
  region: "NA" as const,
  environmentId: ENVIRONMENT_ID,
  appId: APP_ID,
  roleAttribute: "awsRoles",
  clientId: CLIENT_ID,
  clientSecret: AWS_SECRET,
};

export const logger = createLogger();
logger.level = "silent";

/** An answer with `json` as its body. */
export const answer = (status: number, json: unknown): Response =>
  new Response(JSON.stringify(json), {
    headers: { "Content-Type": "application/json" },
    status,
  });

type Handler = (init: RequestInit) => Promise<Response> | Response;

const HOSTS = new Set(["auth.pingone.com", "api.pingone.com"]);

/**
 * Stubs `fetch` with `handlers`, keyed by `METHOD host path` on the NA
 * hosts. A call no handler takes fails the test.
 */
export const stubPingOne = (handlers: Record<string, Handler>) => {
  const fetch = vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input);
    if (!HOSTS.has(url.host)) throw new Error(`unexpected host ${url.host}`);
    const key = `${init.method} ${url.host}${url.pathname}`;
    const handler = handlers[key];
    if (handler === undefined) throw new Error(`no handler for ${key}`);
    return handler(init);
  });
  vi.stubGlobal("fetch", fetch);
  return {
    fetch,
    calls: () =>
      fetch.mock.calls.map(([url, init]) => {
        const { host, pathname } = new URL(url);
        return `${init?.method} ${host}${pathname}`;
      }),
  };
};

/** The `ConnectorError` `run` fails with. */
export const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error;
    throw error;
  }
  throw new Error("expected the call to throw");
};
