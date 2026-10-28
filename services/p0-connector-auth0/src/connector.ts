/**
 * The contract P0's control plane builds its typed client against.
 *
 * The router is exported as a type only, so importing this loads no handler
 * and neither cloud's secret-manager SDK, and needs no `DOMAIN_ALLOW_PATTERN`.
 * The parsers are values: the control plane validates with the same ones.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const Auth0ConnectorSpec = connectorSpec;
export type Auth0ConnectorSpec = typeof connectorSpec;
export type Auth0ConnectorRouter = typeof connectorRouter;

export { spec as organizationSpec } from "./accesses/organization/definition.ts";
export { spec as permissionSpec } from "./accesses/permission/definition.ts";
export { spec as roleSpec } from "./accesses/role/definition.ts";
export {
  type ClientSecret as Auth0ClientSecret,
  TENANT_PATTERN as AUTH0_TENANT_PATTERN,
  type TenantCredentials as Auth0TenantCredentials,
} from "./credentials.ts";
export { REQUIRED_SCOPES as AUTH0_REQUIRED_SCOPES } from "./auth0/scopes.ts";
export {
  type InstallValidation as Auth0InstallValidation,
  installValidation,
} from "./install/definition.ts";
