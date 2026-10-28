import { z } from "zod";

/**
 * The user to find, as P0 sends it: the requestor's P0 email. Each access
 * type extends this with the Databricks identity P0 recorded at stage, which
 * revoke looks the user up by instead.
 */
export const userBody = z.object({ email: z.email() });

/**
 * Whether a call is part of a grant or a revoke, which the control plane sets
 * from the request's status. Every access type's request context carries it,
 * because the policies can't say: a revoke whose access an open sibling
 * request still holds removes nothing, just like a grant. A call that removes
 * access is a revoke whatever this says, which covers the calls that roll
 * back a failed grant. Each access type's `setPoliciesForUser` says how it
 * tells.
 */
export const operation = z.enum(["grant", "revoke"]);

/** What every lister returns: the framework's `SelectItem`s. */
export const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();
