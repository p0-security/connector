import { ConnectorError, createLogger } from "@p0security/connector-core";
import { generateKeyPairSync } from "node:crypto";
import { vi } from "vitest";

export const KEYS = generateKeyPairSync("rsa", { modulusLength: 2048 });

export const JWK = {
  ...KEYS.privateKey.export({ format: "jwk" }),
  kid: "key-1",
};

export const AWS_SECRET = {
  manager: "aws" as const,
  region: "us-west-2",
  secretId: "okta-service-app-key",
};

export const DOMAIN = "acme.okta.com";

export const APP_ID = "0oa1aws2federation3x";

export const CLIENT_ID = "0oa9service8app7id6x";

export const APP_INPUT = {
  domain: DOMAIN,
  appId: APP_ID,
  clientId: CLIENT_ID,
  privateKey: AWS_SECRET,
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

/**
 * Stubs `fetch` with `handlers`, keyed by `METHOD path` on {@link DOMAIN}. A
 * call no handler takes fails the test.
 */
export const stubOkta = (handlers: Record<string, Handler>) => {
  const fetch = vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input);
    if (url.host !== DOMAIN) throw new Error(`unexpected host ${url.host}`);
    const handler = handlers[`${init.method} ${url.pathname}`];
    if (handler === undefined) {
      throw new Error(`no handler for ${init.method} ${url.pathname}`);
    }
    return handler(init);
  });
  vi.stubGlobal("fetch", fetch);
  return {
    fetch,
    calls: () =>
      fetch.mock.calls.map(
        ([url, init]) => `${init?.method} ${new URL(url).pathname}`
      ),
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
