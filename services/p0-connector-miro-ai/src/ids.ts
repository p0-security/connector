import { z } from "zod";

/**
 * The ids the connector sends Miro. Each becomes a URL path segment, so each
 * is held to a shape with no room for a `/`, a `?` or a `.`-only name,
 * before the client encodes it again (`fillRoute` in miro/client.ts).
 */

/**
 * A Miro user's id, which is also their board member id (spec V1): a decimal
 * number too large for a JavaScript number, so always a string.
 */
export const memberId = z
  .string()
  .regex(/^[0-9]{1,20}$/, "must be a Miro user id");

/**
 * A Miro board's id, as in its URL: `/app/board/uXjVOakxTk0=/`. Letters,
 * digits, `_`, `-` and the `=` of its padding.
 */
export const boardId = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,62}={0,2}$/, "must be a Miro board id");

/**
 * The principal's email, as P0 holds it. Not `z.email()` on purpose: the
 * connector matches it against the team's members, ignoring case, and
 * refuses one it doesn't find with a message the requester reads.
 */
export const email = z.string().min(1);
