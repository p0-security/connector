import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { workspaceContext } from "../../databricks/workspaces.ts";
import {
  userBody as commonUserBody,
  listerResponse,
  operation,
} from "../common/definition.ts";

/**
 * The Unity Catalog privileges P0 may grant, in the form the permissions API
 * takes them.
 *
 * The list is closed. `MANAGE`, `ALL_PRIVILEGES`, ownership and
 * `EXTERNAL_USE_SCHEMA` are deliberately absent, and every parser refuses
 * them (see {@link NEVER_GRANTABLE_PRIVILEGES}).
 *
 * Only what P0 adds is held to this list: a grant's policies, and every
 * privilege any call adds, which the handler checks. A request's stored
 * grants (`requestGrants`) and a call's policies may name any privilege
 * {@link GRANT_KEY_PRIVILEGE} matches, except the never-grantable ones.
 * Otherwise dropping a privilege from this list would leave every open
 * request that granted it impossible to revoke, and, since a revoke's
 * policies are its open siblings' stored grants, every other revoke on the
 * same securables too. P0's control plane does the same with the grants it
 * stores.
 */
export const UC_PRIVILEGES = [
  "APPLY_TAG",
  "BROWSE",
  "CREATE_FUNCTION",
  "CREATE_MATERIALIZED_VIEW",
  "CREATE_MODEL",
  "CREATE_SCHEMA",
  "CREATE_TABLE",
  "CREATE_VOLUME",
  "EXECUTE",
  "MODIFY",
  "READ_VOLUME",
  "REFRESH",
  "SELECT",
  "USE_CATALOG",
  "USE_SCHEMA",
  "WRITE_VOLUME",
] as const;

export type UcPrivilege = (typeof UC_PRIVILEGES)[number];

/** Whether P0 grants `privilege`, i.e. it is one of {@link UC_PRIVILEGES}. */
export const isUcPrivilege = (privilege: string): privilege is UcPrivilege =>
  UC_PRIVILEGES.some((name) => name === privilege);

/**
 * Privileges P0 never grants or revokes, in every spelling a caller might
 * send. Both the policy parser and the stored-grant parser refuse them, so
 * not even a revoke can name one.
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

/**
 * Any Unity Catalog privilege name, in the API's underscored upper-case form,
 * unanchored. This is the privilege part of a grant key, and what a stored
 * grant may name.
 */
export const PRIVILEGE_NAME = "[A-Z][A-Z0-9_]*";

const GRANT_KEY_PRIVILEGE = new RegExp(`^${PRIVILEGE_NAME}$`);

export const SECURABLE_TYPES = [
  "catalog",
  "schema",
  "table",
  "volume",
  "function",
] as const;

export type SecurableType = (typeof SECURABLE_TYPES)[number];

/** How many dot-separated parts a securable's full name has. */
export const NAME_PARTS: Record<SecurableType, number> = {
  catalog: 1,
  schema: 2,
  table: 3,
  volume: 3,
  function: 3,
};

/**
 * Whether `fullName` has exactly as many non-empty parts as `type` implies
 * (`catalog`, `catalog.schema` or `catalog.schema.object`), so that its first
 * part is always the catalog it sits in.
 */
const hasNamePartsFor = (type: SecurableType, fullName: string) => {
  const parts = fullName.split(".");
  return parts.length === NAME_PARTS[type] && parts.every((part) => !!part);
};

const FULL_NAME_ERROR =
  "Full name must be catalog, catalog.schema or catalog.schema.object to match its securable type";

/** One part of a three-level name: a catalog or schema name. */
const namePart = z.string().min(1);

const securable = z
  .object({
    type: z.enum(SECURABLE_TYPES),
    fullName: z.string().min(1),
  })
  .refine(({ type, fullName }) => hasNamePartsFor(type, fullName), {
    error: FULL_NAME_ERROR,
    path: ["fullName"],
  });

export type Securable = z.infer<typeof securable>;

/**
 * A Databricks `userName`: an email, or a Microsoft Entra user principal name
 * (UPN), which for a guest looks like
 * `alice_example.com#EXT#@contoso.onmicrosoft.com`. Zod's default email
 * pattern refuses the `#`, so this takes the HTML5 one, which allows it and
 * still requires exactly one `@`. Domain verification matches the domain
 * after it, never the guest's home domain in the local part.
 */
const databricksUserName = z.email({ pattern: z.regexes.html5Email });

/**
 * The user to grant to. `email` is the requestor's P0 email. `userName`, when
 * present, is the email P0 recorded at stage, which is the Databricks
 * username it granted to, so a revoke names the same principal even if the
 * requestor's P0 email changed since.
 */
export const userBody = commonUserBody.extend({
  userName: databricksUserName.optional(),
});

export type UserBody = z.infer<typeof userBody>;

/**
 * The email P0 grants to, which is the Databricks username and the principal
 * every Unity Catalog grant names. The parser refuses anything that isn't an
 * email, such as a bare group name or a service principal's application ID.
 */
const userId = databricksUserName;

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

const NEVER_GRANTABLE_ERROR = "P0 never grants or revokes this privilege";

/** Any Unity Catalog privilege name but the never-grantable ones. */
const storedPrivilege = z
  .string()
  .regex(GRANT_KEY_PRIVILEGE, "must be a Unity Catalog privilege name")
  .refine(isGrantable, NEVER_GRANTABLE_ERROR);

/**
 * A grant some open request holds, as `policies` lists them. A revoke's
 * policies are its open siblings' stored grants, which can name a privilege
 * P0 has since stopped granting, so a policy may name any privilege a stored
 * grant may. The parser can't tell a grant from a revoke, so the handler
 * holds a grant's policies, and every privilege any call adds, to
 * {@link UC_PRIVILEGES}.
 */
const policy = grantOf(storedPrivilege);

export type Policy = z.infer<typeof policy>;

/**
 * A grant a request made, which may only ever be revoked. Any privilege name
 * but the never-grantable ones. Grant keys are read with it too.
 */
export const requestGrant = grantOf(storedPrivilege);

export type RequestGrant = z.infer<typeof requestGrant>;

/**
 * Lister queries. The framework passes `list` only the query, so each one
 * carries the context to authenticate with, which names the workspace by its
 * ID and URL. P0 lists workspaces from its own installed items, so there is
 * no `workspaces` query.
 */
const listerQuery = z.discriminatedUnion("type", [
  // The workspace's Unity Catalog metastore: one item keyed by the metastore
  // ID. Never empty, since a workspace without a metastore can't be bound.
  z.object({ type: z.literal("metastore"), context: workspaceContext }),
  z.object({ type: z.literal("catalogs"), context: workspaceContext }),
  z.object({
    type: z.literal("schemas"),
    context: workspaceContext,
    catalog: namePart,
  }),
  z.object({
    type: z.literal("tables"),
    context: workspaceContext,
    catalog: namePart,
    schema: namePart,
  }),
  z.object({
    type: z.literal("volumes"),
    context: workspaceContext,
    catalog: namePart,
    schema: namePart,
  }),
  z.object({
    type: z.literal("functions"),
    context: workspaceContext,
    catalog: namePart,
    schema: namePart,
  }),
  z.object({
    type: z.literal("directGrants"),
    context: workspaceContext,
    userName: userId,
    securables: z.array(securable).min(1),
  }),
]);

const requestContext = workspaceContext.extend({
  /**
   * The grants this request added. The connector grants only the ones still
   * in `policies` (`policies ∩ requestGrants`) and revokes the ones no
   * remaining request needs (`requestGrants − policies`), which makes the
   * call a revoke whenever there are any.
   */
  requestGrants: z.array(requestGrant),
  operation,
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
