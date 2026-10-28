import { ConnectorError, createLogger } from "@p0security/connector-core";
import { vi } from "vitest";

import { TOKEN_URL } from "../jira/auth.ts";

export const logger = createLogger();

export const CLOUD_ID = "0e5a4f1e-2b7c-4c8d-9f10-3a4b5c6d7e8f";

export const SITE = {
  cloudId: CLOUD_ID,
  adminClientId: "admin-client",
  adminSecret: {
    manager: "gcp" as const,
    projectId: "acme-vault",
    secretId: "jira-admin",
  },
  tenantId: "acme",
};

export const API = `https://api.atlassian.com/ex/jira/${CLOUD_ID}/rest/api/3`;

/** The {@link ConnectorError} `promise` fails with. Any other outcome fails the test. */
export const connectorErrorOf = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ConnectorError) return error;
    throw error;
  }
  throw new Error("expected a failure");
};

/**
 * Runs `start` with fake timers, skipping every wait between retries, and
 * returns its promise once it has settled.
 */
export const withoutWaits = async <T>(start: () => Promise<T>): Promise<T> => {
  vi.useFakeTimers();
  try {
    const promise = start();
    // Settled below. This keeps a rejection from counting as unhandled first.
    promise.catch(() => undefined);
    await vi.runAllTimersAsync();
    return await promise;
  } finally {
    vi.useRealTimers();
  }
};

export type Reply = {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
};

type FakeResponse = Pick<
  Response,
  "headers" | "json" | "ok" | "status" | "statusText"
>;

export const jsonResponse = (reply: Reply): FakeResponse => {
  const { status, body, headers } = reply;
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    headers: new Headers(headers),
    json: async () => {
      if (body === undefined) throw new SyntaxError("no body");
      return body;
    },
  };
};

/**
 * A fake `fetch` that answers by method and URL. Each key is
 * `<METHOD> <url>`. A value is one reply, or a list answered in turn (the
 * last one repeats). The token endpoint answers with a fresh admin token
 * unless a test sets its own reply. A call with no reply set gets a 418,
 * which the connector doesn't retry.
 */
export const fakeFetch = () => {
  const replies = new Map<string, Reply[]>();
  let tokens = 0;
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    const key = `${init.method} ${url}`;
    const queue = replies.get(key);
    if (queue === undefined) {
      if (url === TOKEN_URL) {
        tokens += 1;
        return jsonResponse({
          status: 200,
          body: { access_token: `admin-token-${tokens}`, expires_in: 3600 },
        });
      }
      return jsonResponse({ status: 418, body: { errorMessages: [key] } });
    }
    const [next, ...rest] = queue;
    if (next === undefined) throw new Error(`no reply set for ${key}`);
    if (rest.length > 0) replies.set(key, rest);
    return jsonResponse(next);
  });
  const reply = (key: string, ...answers: Reply[]) => {
    replies.set(key, answers);
  };
  const calls = () =>
    fetch.mock.calls.map(([url, init]) => `${init.method} ${url}`);
  /** The JSON bodies of the POSTs to `url`, in order. */
  const posted = (url: string) =>
    fetch.mock.calls
      .filter(([callUrl, init]) => callUrl === url && init.method === "POST")
      .map(([, init]): unknown =>
        typeof init.body === "string" ? JSON.parse(init.body) : init.body
      );
  return { fetch, reply, calls, posted };
};
