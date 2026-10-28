/**
 * The contract P0's control plane builds its typed client against.
 *
 * The router is exported as a type only, so importing this loads no handler
 * and neither cloud's secret-manager SDK, and needs no `DOMAIN_ALLOW_PATTERN`.
 * The parsers are values: the control plane validates with the same ones.
 */
import type { ConsolePolicy } from "./accesses/console/definition.ts";
import type { SqlPolicy } from "./accesses/sql/definition.ts";
import type { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const ClickHouseConnectorSpec = connectorSpec;
export type ClickHouseConnectorSpec = typeof connectorSpec;
export type ClickHouseConnectorRouter = typeof connectorRouter;

export { spec as consoleSpec } from "./accesses/console/definition.ts";
export { spec as sqlSpec } from "./accesses/sql/definition.ts";

/** The one policy P0 sends with each request, by access. */
export type ClickHousePolicy = ConsolePolicy | SqlPolicy;
export type {
  ConsolePolicy as ClickHouseConsolePolicy,
  SqlPolicy as ClickHouseSqlPolicy,
};

export {
  CLOUD_ID_PATTERN as CLICKHOUSE_ORGANIZATION_ID_PATTERN,
  ORGANIZATION_ID_MESSAGE as CLICKHOUSE_ORGANIZATION_ID_MESSAGE,
  type OrganizationCredentials,
  organizationCredentials,
  type SecretPointer,
  secretPointer,
} from "./credentials.ts";
export { REQUIRED_PERMISSIONS as CLICKHOUSE_REQUIRED_PERMISSIONS } from "./cloud/permissions.ts";
export { LEVEL_PRIVILEGES as CLICKHOUSE_LEVEL_PRIVILEGES } from "./levels.ts";
export {
  type InstallValidation as ClickHouseInstallValidation,
  installInput,
  installValidation,
} from "./install/definition.ts";
export {
  CLICKHOUSE_REFUSAL_REASONS,
  type ClickHouseRefusalReason,
  clickhouseRefusalReason,
} from "./refusals.ts";
export {
  type RequestContext as ClickHouseRequestContext,
  requestContext,
} from "./accesses/common/definition.ts";
