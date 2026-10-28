import { z } from "zod";

import { tenantCredentials } from "../../credentials.ts";

const email = z.email();

// An Auth0 user id, such as `auth0|abc` or `google-oauth2|123`. It becomes a
// URL path segment, which `segment` encodes and checks.
export const auth0UserId = z.string().min(1).max(256);

// Ids of roles and organizations, such as `rol_abc` and `org_abc`, which also
// become path segments. Nothing but letters, digits, `_` and `-` gets in.
export const auth0Id = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,64}$/, "must be an Auth0 id");

/** The requestor's Auth0 user, as P0 found it by their email. */
const userQuery = { context: tenantCredentials, email, userId: auth0UserId };

/**
 * What every access's `list` answers. `list` gets no request context, so each
 * query carries the credentials. The ones about a user carry the requestor's
 * P0 email, which the allowed domains gate, and the Auth0 user id P0 found
 * for it, which must still have that email.
 *
 * | `type`             | One entry per                  | `key`      | `value`     | `group` |
 * | ------------------ | ------------------------------ | ---------- | ----------- | ------- |
 * | `users`            | Auth0 user with the email      | user id    | connection  | email   |
 * | `roles`            | tenant role                    | role id    | role name   |         |
 * | `apis`             | API                            | identifier | name        |         |
 * | `permissions`      | permission the API defines     | permission | description |         |
 * | `organizations`    | organization                   | org id     | org name    |         |
 * | `user-roles`       | role assigned to the user      | role id    | role name   |         |
 * | `user-permissions` | permission assigned directly,  | permission | permission  | API     |
 * |                    | on the query's API             |            |             |         |
 * | `org-membership`   | the membership                 | `member`   | user id     |         |
 * |                    | then each of the member's roles | role id    | role name   | `role`  |
 *
 * `org-membership` is `[]` when the user isn't a member. A `users` entry
 * without a connection has an empty `value`, and one without an email an
 * empty `group`.
 */
export const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("users"), context: tenantCredentials, email }),
  z.object({ type: z.literal("roles"), context: tenantCredentials }),
  z.object({ type: z.literal("apis"), context: tenantCredentials }),
  z.object({
    type: z.literal("permissions"),
    context: tenantCredentials,
    resourceServerIdentifier: z.string().min(1),
  }),
  z.object({ type: z.literal("organizations"), context: tenantCredentials }),
  z.object({ type: z.literal("user-roles"), ...userQuery }),
  z.object({
    type: z.literal("user-permissions"),
    ...userQuery,
    resourceServerIdentifier: z.string().min(1),
  }),
  z.object({
    type: z.literal("org-membership"),
    ...userQuery,
    organizationId: auth0Id,
  }),
]);

export type ListerQuery = z.infer<typeof listerQuery>;

/** What every lister returns: the framework's `SelectItem`s. */
export const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;

/** The `key` of the `org-membership` entry that says the user is a member. */
export const MEMBER = "member";

/** The `group` of each role in an `org-membership` answer. */
export const ROLE_GROUP = "role";

// The requestor's P0 email is the framework's user, as with Docker Hub. The
// Auth0 user P0 found for it travels in the request context.
export const userBody = email;
export const userId = email;

/**
 * What every access's request context starts with: the tenant credentials,
 * the request, and the Auth0 user P0 found for the requestor's email. A grant
 * checks that the user still has the email. A revoke takes back from that
 * user whatever its email is now.
 */
export const baseRequestContext = tenantCredentials.extend({
  requestId: z.string(),
  auth0UserId,
});
