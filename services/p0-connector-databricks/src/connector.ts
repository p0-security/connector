/**
 * The contract the P0 control plane builds its typed client against: the
 * spec's parsers, the router's type, and the schemas and helpers it shares
 * with the connector.
 *
 * A separate entry point from `index.ts`, which constructs the Lambda handler
 * on import. The control plane needs the contract, not the handler, so
 * nothing here loads the handler, the routers or `@aws-sdk/client-sts`: the
 * router is imported for its type only.
 */
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const DatabricksConnectorSpec = connectorSpec;
export type DatabricksConnectorSpec = typeof connectorSpec;
export type DatabricksConnectorRouter = typeof connectorRouter;

export {
  type InstallValidation as DatabricksInstallValidation,
  type InstallValidationInput as DatabricksInstallValidationInput,
} from "./install/definition.ts";
export {
  NEVER_GRANTABLE_PRIVILEGES as DatabricksNeverGrantablePrivileges,
  SECURABLE_TYPES as DatabricksSecurableTypes,
  UC_PRIVILEGES as DatabricksUcPrivileges,
  userBody as DatabricksPrivilegeUserBodySchema,
  type Securable as DatabricksSecurable,
  type SecurableType as DatabricksSecurableType,
  type UcPrivilege as DatabricksUcPrivilege,
  type UserBody as DatabricksPrivilegeUserBody,
} from "./accesses/privilege/definition.ts";
export {
  userBody as DatabricksAdminUserBodySchema,
  type UserBody as DatabricksAdminUserBody,
} from "./accesses/admin/definition.ts";
export {
  grantKey as databricksGrantKey,
  parseGrantKey as parseDatabricksGrantKey,
} from "./accesses/privilege/unity-catalog.ts";
