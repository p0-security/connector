import { request } from "node:https";

import type { App } from "../account.ts";

export const TIMEOUT_MS = 10_000;

export type Call = {
  method: "GET" | "PATCH";
  /** The path and query after the PingFederate URL. */
  path: string;
  headers?: Record<string, string>;
  body?: string;
};

export type Reply = { status: number; body: string };

/**
 * Sends one call to PingFederate's runtime and gets the reply, whatever its
 * status.
 */
export const callPingFederate = (
  {
    pingFederateUrl,
    caCertificate,
  }: Pick<App, "caCertificate" | "pingFederateUrl">,
  { method, path, headers = {}, body }: Call
): Promise<Reply> =>
  new Promise((resolve, reject) => {
    // `fetch` takes no CA certificate.
    const outgoing = request(
      `${pingFederateUrl}${path}`,
      {
        method,
        headers,
        timeout: TIMEOUT_MS,
        ...(caCertificate === undefined ? {} : { ca: caCertificate }),
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => (text += chunk));
        response.on("end", () =>
          resolve({ status: response.statusCode ?? 0, body: text })
        );
        response.on("error", reject);
      }
    );
    outgoing.on("timeout", () =>
      outgoing.destroy(
        Object.assign(new Error("PingFederate didn't answer in time"), {
          code: "ETIMEDOUT",
        })
      )
    );
    outgoing.on("error", reject);
    outgoing.end(body);
  });
