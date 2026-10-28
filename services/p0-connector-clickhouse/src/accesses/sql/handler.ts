import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  newResourceHierarchyRouter,
} from "@p0security/connector";

import { sqlConsolePolicy } from "../../cloud/roles.ts";
import { levelGrants } from "../../levels.ts";
import {
  type ToPolicies,
  newCommonClickHousePrimitives,
  newPolicyPrimitives,
} from "../common/primitives.ts";
import { type SqlPolicy, spec } from "./definition.ts";

/**
 * The `sql` access: a level on the whole service, a database or one object
 * in it, as GRANT statements in SQL console on the service.
 */
export const toSqlPolicies: ToPolicies<SqlPolicy> = (
  { level, object },
  { serviceId }
) => [sqlConsolePolicy(serviceId, { grants: levelGrants({ level, object }) })];

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceHierarchyRouter(t, spec, ({ logger }: ConnectorContext) => ({
    ...newCommonClickHousePrimitives(logger),
    ...newPolicyPrimitives(logger, toSqlPolicies),
  }));
