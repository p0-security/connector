import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { agentContext } from "../../agent/context.ts";
import { agentName } from "../../agent/name.ts";
import { accountContext, workspaceId } from "../../databricks/context.ts";

/**
 * The Unity Catalog privileges P0 grants an agent, in the form the
 * permissions API takes them: what the `read` and `write` levels expand to,
 * with the parents' USE privileges. The list is closed, so a grant's policies
 * can never name `MANAGE`, `ALL_PRIVILEGES`, ownership or `CREATE_SCHEMA`.
 */
export const DATA_PRIVILEGES = [
  "SELECT",
  "READ_VOLUME",
  "EXECUTE",
  "USE_CATALOG",
  "USE_SCHEMA",
  "MODIFY",
  "WRITE_VOLUME",
  "CREATE_TABLE",
  "CREATE_VOLUME",
  "CREATE_FUNCTION",
  "CREATE_MATERIALIZED_VIEW",
] as const;

/**
 * Privileges P0 never grants or revokes, in every spelling a caller might
 * send. The stored-grant parser refuses them, so not even a revoke can name
 * one.
 */
export const NEVER_GRANTABLE_PRIVILEGES = [
  "MANAGE",
  "ALL_PRIVILEGES",
  "ALL PRIVILEGES",
  "OWNERSHIP",
  "OWNER",
  "EXTERNAL_USE_SCHEMA",
  "EXTERNAL USE SCHEMA",
] as const;

const isGrantable = (privilege: string) =>
  !NEVER_GRANTABLE_PRIVILEGES.some((name) => name === privilege.toUpperCase());

/** What an agent can be granted on. The permissions API takes a view as a `table`. */
export const SECURABLE_TYPES = [
  "catalog",
  "schema",
  "table",
  "volume",
] as const;

export type SecurableType = (typeof SECURABLE_TYPES)[number];

/** How many dot-separated parts a securable's full name has. */
export const NAME_PARTS: Record<SecurableType, number> = {
  catalog: 1,
  schema: 2,
  table: 3,
  volume: 3,
};

/**
 * Whether `fullName` has exactly as many non-empty parts as `type` implies,
 * so that its first part is always the catalog it sits in.
 */
const hasNamePartsFor = (type: SecurableType, fullName: string) => {
  const parts = fullName.split(".");
  return parts.length === NAME_PARTS[type] && parts.every((part) => !!part);
};

const FULL_NAME_ERROR =
  "Full name must be catalog, catalog.schema or catalog.schema.object to match its securable type";

/** One part of a three-level name: a catalog or schema name. */
const namePart = z.string().min(1);

export const securable = z
  .object({
    type: z.enum(SECURABLE_TYPES),
    fullName: z.string().min(1),
  })
  .refine(({ type, fullName }) => hasNamePartsFor(type, fullName), {
    error: FULL_NAME_ERROR,
    path: ["fullName"],
  });

export type Securable = z.infer<typeof securable>;

const grantOf = <Privilege extends z.ZodType<string>>(privilege: Privilege) =>
  z
    .object({
      securableType: z.enum(SECURABLE_TYPES),
      fullName: z.string().min(1),
      privilege,
    })
    .refine(
      ({ securableType, fullName }) => hasNamePartsFor(securableType, fullName),
      { error: FULL_NAME_ERROR, path: ["fullName"] }
    );

/** One privilege P0 grants on one securable. */
const policy = grantOf(z.enum(DATA_PRIVILEGES));

export type Policy = z.infer<typeof policy>;

/**
 * A grant the request added, which revoke removes. Any Unity Catalog
 * privilege name but the never-grantable ones, so a grant P0 has since
 * stopped making can still be revoked.
 */
export const requestGrant = grantOf(
  z
    .string()
    .regex(/^[A-Z][A-Z0-9_]*$/, "must be a Unity Catalog privilege name")
    .refine(isGrantable, "P0 never grants or revokes this privilege")
);

export type RequestGrant = z.infer<typeof requestGrant>;

/** A SQL warehouse ID, which goes into a URL path. */
const warehouseId = z
  .string()
  .regex(/^[A-Za-z0-9]+$/, "must be a SQL warehouse ID");

/**
 * Everything one data grant's calls read. On top of the agent principal's
 * context, it names the warehouse the agent queries on, the securable the
 * level is granted on, the grants the request added, and who takes over what
 * the agent created when it is revoked. A context from an older app that
 * still names `mcpService` parses, and the field is dropped.
 */
export const requestContext = agentContext.extend({
  warehouseId,
  securable,
  /** Every grant the request added, parents' USE privileges included. Revoke removes only these. */
  addedGrants: z.array(requestGrant),
  /**
   * Who owns what the agent created once it is revoked: a group's display
   * name, a user's `userName` or a service principal's application ID.
   */
  ownerPrincipal: z.string().min(1),
});

export type RequestContext = z.infer<typeof requestContext>;

/**
 * Lister queries. The framework passes `list` only the query, so each one
 * carries the account context to authenticate with.
 */
export const listerQuery = z.discriminatedUnion("type", [
  // Every running workspace in the account, valued `<name> (<host>)`.
  z.object({ type: z.literal("workspaces"), context: accountContext }),
  // One workspace, valued by the host P0 built for it.
  z.object({
    type: z.literal("workspace"),
    context: accountContext,
    workspaceId,
  }),
  z.object({
    type: z.literal("warehouses"),
    context: accountContext,
    workspaceId,
  }),
  z.object({
    type: z.literal("catalogs"),
    context: accountContext,
    workspaceId,
  }),
  z.object({
    type: z.literal("schemas"),
    context: accountContext,
    workspaceId,
    catalog: namePart,
  }),
  z.object({
    type: z.literal("tables"),
    context: accountContext,
    workspaceId,
    catalog: namePart,
    schema: namePart,
  }),
  z.object({
    type: z.literal("volumes"),
    context: accountContext,
    workspaceId,
    catalog: namePart,
    schema: namePart,
  }),
]);

export type ListerQuery = z.infer<typeof listerQuery>;

/** What every lister returns: the framework's `SelectItem`s. */
const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export const schema = {
  userBody: agentName,
  userId: agentName,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
