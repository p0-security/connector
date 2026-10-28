import { z } from "zod";

import { organizationCredentials, serviceId } from "../../credentials.ts";

/**
 * What every request-time call carries, for each of the two accesses:
 *
 * - `requestId`: the P0 request's ID. The role's name holds only its first
 *   4 characters, so the connector logs the whole ID.
 * - `organization`: the organization's credentials, which say which
 *   organization the call is for.
 * - `serviceId`: the one service the access is on.
 * - `description`: `P0 request <requestId> for <email>: <access>`. ClickHouse
 *   Cloud roles have no description, so the connector only logs it.
 */
export const requestContext = z.object({
  requestId: z.string().min(1),
  organization: organizationCredentials,
  serviceId,
  description: z.string(),
});

export type RequestContext = z.infer<typeof requestContext>;

/** The kinds of object `objects` lists, in its `group`. */
export const OBJECT_KINDS = [
  "database",
  "table",
  "view",
  "materialized-view",
  "dictionary",
] as const;

export type ObjectKind = (typeof OBJECT_KINDS)[number];

/** The fields a `service` answer holds, one item each, in this order. */
export const SERVICE_FIELDS = ["id", "name", "version", "byoc"] as const;

/** A database or table name, as a request names it, which a grant quotes. */
export const objectName = z.string().min(1).max(1024);

/**
 * What every access's `list` answers. `list` gets no request context, so each
 * query carries the organization's credentials.
 *
 * | `type`     | One item per                     | `key`         | `value`       | `group` |
 * | ---------- | -------------------------------- | ------------- | ------------- | ------- |
 * | `member`   | member with the email            | user ID       | email         |         |
 * | `services` | service in the organization      | service ID    | service name  |         |
 * | `service`  | field of the service             | field name    | field value   |         |
 * | `objects`  | database, table, view,           | `db` or       | same as `key` | kind    |
 * |            | materialized view or dictionary  | `db.name`     |               |         |
 *
 * - `member` is `[]` when no member has the email, ignoring case, and refuses
 *   with `ambiguous_member` when more than one has. An email whose domain
 *   `DOMAIN_ALLOW_PATTERN` doesn't allow is refused with `domain_not_allowed`.
 * - `service` is `[]` when the service isn't there. Its fields are
 *   {@link SERVICE_FIELDS}, every value a string: `version` is the ClickHouse
 *   version (`""` when Cloud doesn't report one), `byoc` is `"true"` or
 *   `"false"`.
 * - `objects` leaves out ClickHouse's own databases, any database whose name
 *   holds a `.`, temporary tables and materialized views' hidden tables. Its
 *   `group` is one of {@link OBJECT_KINDS}. A key splits on its first `.`.
 */
export const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("member"),
    context: organizationCredentials,
    email: z.email(),
  }),
  z.object({ type: z.literal("services"), context: organizationCredentials }),
  z.object({
    type: z.literal("service"),
    context: organizationCredentials,
    serviceId,
  }),
  z.object({
    type: z.literal("objects"),
    context: organizationCredentials,
    serviceId,
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

/**
 * The requestor's email, which is both the framework's user body and its
 * user ID: P0 creates no ClickHouse Cloud user, and binds the role to the
 * member that has the email.
 */
export const email = z.email();

/**
 * The custom role's name, which is both the framework's resource body and
 * its resource ID: P0 generates it as `p0_…`, in lower snake case, at most
 * 64 characters. Every primitive finds the role by it.
 */
export const roleName = z.string().min(1).max(64);

/**
 * What every ClickHouse access's parsers share: the user, the resource, the
 * request context and the lister. Each access adds only its policy.
 */
export const accessSchemas = {
  userBody: email,
  userId: email,
  resourceBody: roleName,
  resourceId: roleName,
  listerQuery,
  listerResponse,
  requestContext,
};
