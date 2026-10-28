import { ConnectorError, type Logger } from "@p0security/connector";

import type { ApiKey } from "../api-key.ts";
import {
  ClickHouseError,
  basicCredentials,
  failureOf,
  readBody,
  readError,
  retryAfterOf,
  secretsOf,
  withoutSecrets,
} from "../cloud/api.ts";
import { CLOUD_ID_PATTERN } from "../credentials.ts";

/** The Query API's one host. The connector runs endpoints there and nowhere else. */
export const QUERY_HOST = "queries.clickhouse.cloud";

/** How long an endpoint run may take before it's abandoned, in milliseconds. */
export const QUERY_TIMEOUT = 30_000;

/**
 * The only URL an endpoint may be run at. ClickHouse Cloud gives each
 * endpoint its `url`, and the connector won't send the key anywhere else.
 */
const RUN_URL = new RegExp(
  `^https://queries\\.clickhouse\\.cloud/run/(${CLOUD_ID_PATTERN.source.slice(1, -1)})$`
);

/** An endpoint to run: its name, for messages and logs, and its URL. */
export type Runnable = { name: string; url: string };

/** One value per query parameter the endpoint's SQL names. */
export type QueryVariables = Record<string, boolean | number | string>;

/**
 * The run's rows: ClickHouse's `JSONEachRow`, one JSON value per line. An
 * unreadable line fails the whole run, as `unknown`.
 */
const parseRows = (log: Logger, name: string, text: string): unknown[] =>
  text
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line, index): unknown => {
      try {
        return JSON.parse(line);
      } catch {
        // The line number only: a row is the customer's data.
        log.warn({ endpoint: name, line: index + 1 }, "unreadable row");
        throw new ConnectorError({
          type: "unknown",
          message: `ClickHouse Cloud returned rows from P0's Query API endpoint ${name} that P0 can't read.`,
          payload: { endpoint: name },
        });
      }
    });

/**
 * Runs one of P0's Query API endpoints at its own `url`, as the key, and
 * returns its rows.
 *
 * `POST <url>` with Basic auth, `x-clickhouse-endpoint-version: 2` and the
 * body `{format: "JSONEachRow", queryVariables}`. The URL must be
 * `https://queries.clickhouse.cloud/run/<uuid>`, or nothing is sent.
 * Redirects are refused, a run that takes over 30 seconds is abandoned, and
 * the key is cut out of every error.
 */
export const runEndpoint = async ({
  log,
  key,
  endpoint: { name, url },
  queryVariables = {},
}: {
  log: Logger;
  key: ApiKey;
  endpoint: Runnable;
  queryVariables?: QueryVariables;
}): Promise<unknown[]> => {
  const id = RUN_URL.exec(url)?.[1];
  if (id === undefined) {
    // The URL isn't quoted: the connector won't repeat where it was sent.
    log.warn({ endpoint: name }, "an endpoint's URL isn't on the Query API");
    throw new ConnectorError({
      type: "unknown",
      message: `ClickHouse Cloud gave P0's Query API endpoint ${name} a URL that isn't on ${QUERY_HOST}, so P0 won't run it.`,
      payload: { endpoint: name },
    });
  }
  const path = `/run/${id}`;
  const secrets = secretsOf(key);
  const noAnswer = (error: unknown): never => {
    log.warn(
      { endpoint: name, failure: failureOf(error, secrets) },
      "running a Query API endpoint failed"
    );
    throw new ClickHouseError({
      api: "query",
      method: "POST",
      path,
      status: undefined,
      messages: withoutSecrets(
        [error instanceof Error ? error.message : String(error)],
        secrets
      ),
    });
  };
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Accept: "application/x-ndjson, application/json",
      Authorization: `Basic ${basicCredentials(key)}`,
      "Content-Type": "application/json",
      "x-clickhouse-endpoint-version": "2",
    },
    body: JSON.stringify({ format: "JSONEachRow", queryVariables }),
    // A redirect would resend the key somewhere else.
    redirect: "error",
    signal: AbortSignal.timeout(QUERY_TIMEOUT),
  }).catch(noAnswer);

  // The connection can still drop while either body arrives.
  if (!response.ok) {
    const data = await readBody(response).catch(noAnswer);
    const error = new ClickHouseError({
      api: "query",
      method: "POST",
      path,
      status: response.status,
      messages: readError(data, secrets),
      retryAfter:
        response.status === 429 ? retryAfterOf(response.headers) : undefined,
    });
    log.warn(
      {
        endpoint: name,
        status: error.status,
        messages: error.messages,
        retryAfter: error.retryAfter,
      },
      "running a Query API endpoint returned a non-2xx response"
    );
    throw error;
  }
  const text = await response.text().catch(noAnswer);

  const rows = parseRows(log, name, text);
  log.debug(
    { endpoint: name, status: response.status, rows: rows.length },
    "ran a Query API endpoint"
  );
  return rows;
};
