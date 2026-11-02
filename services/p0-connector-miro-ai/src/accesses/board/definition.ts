import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { boardId, email, memberId } from "../../ids.ts";
import { BOARD_ROLES_BY_RANK } from "../../miro/roles.ts";
import { team } from "../../team.ts";

/**
 * The board roles P0 grants, weakest first. Never `coowner` or `owner`:
 * those can share the board, which P0 keeps to the connector user.
 */
export const boardRole = z
  .enum(BOARD_ROLES_BY_RANK)
  .exclude(["coowner", "owner"]);

export type BoardRole = z.infer<typeof boardRole>;

/**
 * The role the member held on the board before P0 granted, which a revoke
 * restores when no sibling request still holds a role. `none` is someone
 * who wasn't a direct member, whom a revoke removes again.
 */
export const priorRole = z.enum([...BOARD_ROLES_BY_RANK, "none"]);

export type PriorRole = z.infer<typeof priorRole>;

/**
 * A board role this request or a sibling holds, on the same member and
 * board. A grant raises the member to the request's own role, and only
 * raises. A revoke lowers the member to the highest that remains, or to
 * `priorRole` when none does, and only lowers.
 */
const policy = boardRole;

/**
 * The board member to act on. P0 groups a principal's open requests by this
 * body, so siblings are requests on the same board, and locks on it for
 * that principal. The connector reads the team from the request context.
 */
export const userBody = z.object({
  boardId,
  memberId,
  teamId: team.shape.teamId,
});

export type UserBody = z.infer<typeof userBody>;

/** The framework's user id is the member's Miro user id. */
export const userId = memberId;

/**
 * Whether P0 is granting or revoking. A call is a revoke when this says so,
 * or when the request's own role is missing from `policies`: a failed
 * grant's rollback still says `grant`.
 */
export const operation = z.enum(["grant", "revoke"]);

/**
 * The team, the request, the principal's email, the operation, the board
 * and the role, and the member's role before P0 granted. `setPoliciesForUser`
 * gets a member id and no email, so the email travels here, for a grant to
 * check the member still has it.
 *
 * `priorRole` is required: a context that lost it must fail to parse, not
 * read as "held none" and remove a member who was there before P0 (spec
 * section 4, revoke step 4).
 */
export const requestContext = team.extend({
  boardId,
  email,
  operation,
  priorRole,
  requestId: z.string().min(1),
  role: boardRole,
});

export type RequestContext = z.infer<typeof requestContext>;

/**
 * What the access's `list` answers. `list` gets no request context, so each
 * query carries the team as its `context`. Each answers the framework's
 * `SelectItem`s, `{ key, value, group? }`.
 *
 * - `member { email }`: `[{ key: <user id>, value: <email> }]`, the team's
 *   one member with the email, ignoring case. Refuses with `not_in_team`
 *   when no member has it, and `pending_invite` when the member hasn't
 *   created a Miro account yet. P0 calls it when a request is made.
 * - `member-state { boardId, memberId }`: `[{ key: "role", value: <role> }]`,
 *   the member's role on the board, `none` when they aren't a direct
 *   member. P0 calls it when it stages a grant, and records the answer as
 *   the grant's prior role.
 * - `boards`: the team's boards the connector user owns or co-owns, so can
 *   share, as `[{ key: <board id>, value: <board name> }]`.
 * - Each refuses with `member_changed` (`payload.changed: "team"`) when the
 *   access token belongs to another team than the context's.
 */
export const listerQuery = z.discriminatedUnion("type", [
  z.object({ context: team, email, type: z.literal("member") }),
  z.object({
    boardId,
    context: team,
    memberId,
    type: z.literal("member-state"),
  }),
  z.object({ context: team, type: z.literal("boards") }),
]);

export type ListerQuery = z.infer<typeof listerQuery>;

/** What every lister returns: the framework's `SelectItem`s. */
export const listerResponse = z
  .object({ group: z.string().optional(), key: z.string(), value: z.string() })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;

export const schema = {
  listerQuery,
  listerResponse,
  policy,
  requestContext,
  userBody,
  userId,
};

export const spec = newZodResourceRootParsers(schema);
