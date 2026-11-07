import { ConnectorError, type LogQuery } from "@p0security/connector-core";
import { createHash } from "node:crypto";
import { z } from "zod";

/** A time slice, `[start, end)` in epoch milliseconds. */
const SliceSchema = z.tuple([z.number().int(), z.number().int()]);
export type Slice = z.infer<typeof SliceSchema>;

/**
 * Where a read left off. Opaque to P0, which signs it and sends it back.
 *
 * - `h`: the query it belongs to (see {@link queryHash}).
 * - `q`: the running Logs Insights query over slice `s`.
 * - `r`: the slices still to read, oldest first.
 * - `f`: the running freshness query, for the `lag` gap.
 */
const CursorSchema = z.strictObject({
  v: z.literal(1),
  h: z.string(),
  q: z.string().min(1),
  s: SliceSchema,
  r: z.array(SliceSchema),
  f: z.string().min(1).optional(),
});
export type CursorState = Omit<z.infer<typeof CursorSchema>, "h" | "v">;

/**
 * Identifies the query a cursor was made for, so a cursor can't be replayed
 * against another query. The window's end is left out: for a live grant P0
 * rebuilds it as "now" on every call.
 */
export const queryHash = (query: LogQuery, logGroupName: string) =>
  createHash("sha256")
    .update(
      JSON.stringify({
        ...query,
        window: { start: query.window.start },
        logGroupName,
      })
    )
    .digest("base64url")
    .slice(0, 22);

export const encodeCursor = (hash: string, state: CursorState) =>
  Buffer.from(JSON.stringify({ v: 1, h: hash, ...state })).toString(
    "base64url"
  );

const invalid = (message: string) =>
  new ConnectorError({ type: "validation_error", message, payload: {} });

export const decodeCursor = (cursor: string, hash: string): CursorState => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
  } catch {
    throw invalid("The cursor isn't one this connector made");
  }
  const result = CursorSchema.safeParse(parsed);
  if (!result.success)
    throw invalid("The cursor isn't one this connector made");
  const { v: _, h, ...state } = result.data;
  if (h !== hash) throw invalid("The cursor belongs to a different query");
  return state;
};
