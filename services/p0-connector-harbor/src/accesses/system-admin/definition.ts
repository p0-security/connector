import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  email,
  instance,
  listerResponse,
  userBody,
  userId,
} from "../project-role/definition.ts";

/**
 * A user's system administrator state on Harbor, as the `admin-state` lister
 * reports it:
 *
 * - `none`: not an administrator;
 * - `flag`: Harbor's `sysadmin_flag` is set, which is what this access sets
 *   and clears;
 * - `auth`: administrator through the identity provider's admin group
 *   (`admin_role_in_auth`) only;
 * - `flag_and_auth`: both.
 *
 * Harbor's user list answers `admin_role_in_auth` as `false` for every user,
 * since Harbor works it out only for the signed-in user, so `auth` and
 * `flag_and_auth` are there for a Harbor that one day lists it.
 */
export const harborAdminState = z.enum([
  "none",
  "flag",
  "auth",
  "flag_and_auth",
]);

export type HarborAdminState = z.infer<typeof harborAdminState>;

/**
 * Whether to leave the user a Harbor system administrator. `true` is a grant,
 * which sets the user's `sysadmin_flag`. `false` is a revoke, which clears
 * it only when the request context says the user didn't have it before P0
 * granted, and never sets it.
 */
const policy = z.object({ systemAdmin: z.boolean() });

// `list` gets no request context, so the query carries the instance as its
// `context`. `admin-state` reads the admin state of the Harbor user behind an
// email, `[]` for none or `[{ key: <user id>, value: <HarborAdminState> }]`,
// for the prior state P0 records at stage and the check that the user isn't
// an administrator already.
const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("admin-state"), context: instance, email }),
]);

// What a grant and a revoke need besides the user and the policy.
//
// `email` is the principal's, which a grant checks again (`userId` comes
// without a user body).
//
// `wasSystemAdmin` is whether the user's `sysadmin_flag` was set before P0
// granted, as the `admin-state` lister read it at stage. It is required, with
// no `null`: a context that lost it must fail to parse, not read as "wasn't"
// and take the flag from someone who had it. A revoke clears the flag only
// when it is `false`.
const requestContext = instance.extend({
  requestId: z.string(),
  email,
  wasSystemAdmin: z.boolean(),
});

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
