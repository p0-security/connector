import { ConnectorError, type LogQuery } from "@p0security/connector-core";
import { createHash } from "node:crypto";
import { z } from "zod";

/**
 * Where a read left off. Opaque to P0, which signs it and sends it back.
 *
 * - `h`: the query it belongs to (see {@link queryHash}).
 * - `t`: the Logging page token, absent before the first page.
 * - `e`: the window's end when paging began. `entries.list` wants every
 *   parameter but the token unchanged between pages, so a live grant's
 *   growing end is held here until paging is done.
 */
const CursorSchema = z.strictObject({
  v: z.literal(1),
  h: z.string(),
  t: z.string().min(1).optional(),
  e: z.iso.datetime({ offset: true }),
});

export type CursorState = { pageToken?: string; end: string };

/**
 * Identifies the query a cursor was made for. The window's end is left out:
 * for a live grant P0 rebuilds it as "now" on every call.
 */
export const queryHash = (query: LogQuery) =>
  createHash("sha256")
    .update(JSON.stringify({ ...query, window: { start: query.window.start } }))
    .digest("base64url")
    .slice(0, 22);

export const encodeCursor = (hash: string, { pageToken, end }: CursorState) =>
  Buffer.from(
    JSON.stringify({
      v: 1,
      h: hash,
      ...(pageToken ? { t: pageToken } : {}),
      e: end,
    })
  ).toString("base64url");

const invalid = (message: string) =>
  new ConnectorError({ type: "validation_error", message, payload: {} });

/** Where the cursor's read left off. */
export const decodeCursor = (cursor: string, hash: string): CursorState => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
  } catch {
    throw invalid("The cursor isn't one this connector made");
  }
  const result = CursorSchema.safeParse(parsed);
  if (!result.success) {
    throw invalid("The cursor isn't one this connector made");
  }
  if (result.data.h !== hash) {
    throw invalid("The cursor belongs to a different query");
  }
  const { t, e } = result.data;
  return { ...(t ? { pageToken: t } : {}), end: e };
};
