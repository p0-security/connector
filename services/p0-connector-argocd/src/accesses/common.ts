/**
 * What the connector's accesses share: the user, the instance's host for
 * messages, and the lister's answer.
 */
import { z } from "zod";

import type { Instance } from "../instance.ts";

/**
 * The instance's host, which stands for it in messages: the connector knows
 * an instance only by its URL, not by P0's id for it.
 */
export const hostOf = ({ url }: Pick<Instance, "url">) => new URL(url).host;

// copy of `email` in services/p0-connector-harbor/src/accesses/project-role/definition.ts
//
// The grantee's SSO email, as P0 holds it. Not `z.email()` on purpose: the
// connector decides which emails it writes a line for, against its own
// domain allowlist and the line's own pattern, and refuses the rest with a
// message the requestor reads. Parsing the shape here would turn that
// refusal into a bad request.
export const email = z.string().min(1);

/**
 * The Argo CD user to act on: an SSO user, whom Argo CD knows only by the
 * email its IdP sends. `instanceId` is the id of the instance's install item
 * in P0, and it is there for P0 alone: P0 groups a user's open requests by
 * this body, and locks on it, and one email can be a user of two instances.
 * The connector ignores it.
 */
export const userBody = z.object({
  instanceId: z.string().min(1),
  email,
});

/**
 * The user's id is their email: Argo CD has no id of its own for an SSO
 * user, and a policy line names them by it.
 */
export const userId = email;

/** What `list` answers: `key` is what P0 keeps, `value` what it shows. */
export const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();
