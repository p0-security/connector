import { vi } from "vitest";

import { CLOUDFLARE_API } from "../cloudflare-api.ts";

/** An answer with `json` as its body. */
export const answer = (status: number, json: unknown) =>
  new Response(JSON.stringify(json), {
    headers: { "Content-Type": "application/json" },
    status,
  });

/** A successful v4 envelope around `result`. */
export const ok = (
  result: unknown,
  resultInfo?: { page: number; total_pages: number }
) =>
  answer(200, {
    errors: [],
    messages: [],
    result,
    success: true,
    ...(resultInfo === undefined ? {} : { result_info: resultInfo }),
  });

/** A failed v4 envelope with `errors`. */
export const failed = (
  status: number,
  errors: { code: number; message: string }[]
) => answer(status, { errors, messages: [], result: null, success: false });

type Handler = (url: URL, init: RequestInit) => Promise<Response> | Response;

/**
 * Stubs `fetch` with `handlers`, keyed by `METHOD path` under
 * {@link CLOUDFLARE_API}, without the query. A call no handler takes fails
 * the test.
 */
export const stubCloudflare = (handlers: Record<string, Handler>) => {
  const fetch = vi.fn(async (input: URL | string, init: RequestInit = {}) => {
    const url = new URL(input);
    const path = url.href.slice(CLOUDFLARE_API.length).split("?")[0];
    const handler = handlers[`${init.method ?? "GET"} ${path}`];
    if (handler === undefined) {
      throw new Error(`no handler for ${init.method} ${url.href}`);
    }
    return handler(url, init);
  });
  vi.stubGlobal("fetch", fetch);
  return {
    fetch,
    /** Each call as `METHOD url`, query included. */
    calls: () =>
      fetch.mock.calls.map(([url, init]) => `${init?.method} ${String(url)}`),
    /** The JSON body of call `index`. */
    body: (index: number) =>
      JSON.parse(fetch.mock.calls[index]?.[1]?.body as string) as unknown,
  };
};
