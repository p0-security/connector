/**
 * The contract the P0 control plane builds its typed client against: the
 * router's type, the accesses' parsers, and the schemas the install lookups
 * take and return.
 *
 * Nothing here loads the handlers, the routers or the secret manager client:
 * the router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";

export type JiraAiConnectorRouter = typeof connectorRouter;

export {
  P0_ROLES,
  p0Level,
  rolePolicy,
  spec as roleSpec,
  userBody as roleUserBody,
  type P0Level,
  type RolePolicy,
} from "./accesses/role/definition.ts";
export { spec as tokenSpec } from "./accesses/token/definition.ts";
export {
  accountId,
  accountLookup,
  accountQuery,
  projectKey,
  projectLookup,
  projectQuery,
  projectStyle,
  roleId,
  secretRef,
  site,
  siteLookup,
  siteQuery,
  tenantId,
  type AccountLookup,
  type AccountQuery,
  type ProjectLookup,
  type ProjectQuery,
  type ProjectStyle,
  type SecretRef,
  type Site,
  type SiteLookup,
  type SiteQuery,
} from "./install/definition.ts";
