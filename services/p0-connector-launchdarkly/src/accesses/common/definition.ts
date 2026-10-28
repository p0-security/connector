import { z } from "zod";

import { account, accountId } from "../../account.ts";
import { email, memberId } from "../../ids.ts";

/**
 * The LaunchDarkly member to act on. `accountId` is there for P0, which
 * groups a principal's open requests on the member by this body and locks on
 * it for that principal. The lock is per principal: P0 refuses a request
 * from a second principal on a member that another already has access
 * managed on. The connector reads the account from the request context.
 */
export const userBody = z.object({ accountId, memberId });

export type UserBody = z.infer<typeof userBody>;

/** The framework's user id is the member's `_id`. */
export const userId = memberId;

/**
 * What the access's `list` answers. `list` gets no request context, so each
 * query carries the account as its `context`. Each answers the framework's
 * `SelectItem`s, `{ key, value, group? }`. An item without a `group` is a
 * field of the thing asked about, keyed by the field's name.
 *
 * - `member { email }`: `[{ key: <member _id>, value: <email> }]`, or `[]`
 *   unless exactly one member has the email, ignoring ASCII case, and that
 *   member has verified it, has joined, and isn't the access token's own.
 *   An email outside the domain allowlist is `[]`, without a call.
 * - `member-state { memberId }`: `{ key: "role", value: <base role> }`, then
 *   one item per custom role assigned directly, from the member's own
 *   `customRoles` (`{ key: <role _id>, value: <role _id>, group: "role" }`).
 * - Both refuse with `member_changed` (`payload.changed: "account"`) when
 *   the access token belongs to another account than the context's.
 */
export const listerQuery = z.discriminatedUnion("type", [
  z.object({ context: account, email, type: z.literal("member") }),
  z.object({ context: account, memberId, type: z.literal("member-state") }),
]);

export type ListerQuery = z.infer<typeof listerQuery>;

/** What every lister returns: the framework's `SelectItem`s. */
export const listerResponse = z
  .object({ group: z.string().optional(), key: z.string(), value: z.string() })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;

/**
 * Whether P0 is granting or revoking. A call is a revoke when this says so,
 * or when the request's own target is missing from `policies`: a failed
 * grant's rollback still says `grant`.
 */
export const operation = z.enum(["grant", "revoke"]);

/**
 * What every access's request context starts with: the account, the
 * request, the principal's email and the operation. `setPoliciesForUser`
 * gets a member id and no user body, so the email travels here, for a grant
 * to check the member still has it.
 */
export const baseRequestContext = account.extend({
  email,
  operation,
  requestId: z.string().min(1),
});

export type BaseRequestContext = z.infer<typeof baseRequestContext>;
