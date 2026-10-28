import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  newResourceHierarchyRouter,
  throwAssertNever,
} from "@p0security/connector";

import type { PolicyRequest, Role } from "../../cloud/client.ts";
import { serviceResource, sqlConsolePolicy } from "../../cloud/roles.ts";
import {
  type ToPolicies,
  newCommonClickHousePrimitives,
  newPolicyPrimitives,
} from "../common/primitives.ts";
import { type ConsolePolicy, spec } from "./definition.ts";

/**
 * The ClickHouse Cloud system roles whose service permissions a console role
 * copies, by the names the console shows. A role's name is matched ignoring
 * case.
 */
export const SYSTEM_SERVICE_ROLES = {
  "service-reader": "Service Reader",
  "service-admin": "Service Admin",
} as const;

const SERVICE_PERMISSION = "control-plane:service:";

const unusableSystemRole = (
  name: string,
  organizationId: string,
  why: string
) =>
  new ConnectorError({
    type: "dependency_violation",
    message: `The ClickHouse Cloud organization ${organizationId} ${why}, so P0 can't copy its service permissions.`,
    payload: { organizationId, systemRole: name },
  });

/**
 * The system role's service permissions, scoped to the one service: each of
 * its `control-plane:service:` permissions, its allowed ones in one policy
 * and its denied ones, if any, in another. Every other permission, such as
 * `sql-console:*`, is dropped. The system role is found by `name`,
 * ignoring case. One that isn't there, is there twice or gives no service
 * permission fails as `dependency_violation`.
 */
export const copyServiceRole = (
  roles: readonly Role[],
  {
    name,
    organizationId,
    serviceId,
  }: { name: string; organizationId: string; serviceId: string }
): PolicyRequest[] => {
  const wanted = name.toLowerCase();
  const matches = roles.filter(
    (role) => role.type === "system" && role.name.toLowerCase() === wanted
  );
  const [role, ...others] = matches;
  if (role === undefined || others.length > 0) {
    throw unusableSystemRole(
      name,
      organizationId,
      role === undefined
        ? `has no system role ${name}`
        : `has ${matches.length} system roles named ${name}`
    );
  }
  const copied = (["ALLOW", "DENY"] as const).flatMap(
    (allowDeny): PolicyRequest[] => {
      const permissions = [
        ...new Set(
          role.policies
            .filter((policy) => policy.allowDeny === allowDeny)
            .flatMap((policy) => policy.permissions)
            .filter((permission) => permission.startsWith(SERVICE_PERMISSION))
        ),
      ];
      return permissions.length === 0
        ? []
        : [{ allowDeny, permissions, resources: [serviceResource(serviceId)] }];
    }
  );
  if (!copied.some(({ allowDeny }) => allowDeny === "ALLOW")) {
    throw unusableSystemRole(
      name,
      organizationId,
      `has a system role ${name} that gives no service permission`
    );
  }
  return copied;
};

/**
 * The `console` access: SQL console on the service, read-only or as admin,
 * or a system role's service permissions on the service.
 */
export const toConsolePolicies: ToPolicies<ConsolePolicy> = (
  { consoleRole },
  { organizationId, serviceId, roles }
) => {
  switch (consoleRole) {
    case "sql-console-readonly":
    case "sql-console-admin":
      return [sqlConsolePolicy(serviceId, { roleV2: consoleRole })];
    case "service-reader":
    case "service-admin":
      return copyServiceRole(roles, {
        name: SYSTEM_SERVICE_ROLES[consoleRole],
        organizationId,
        serviceId,
      });
    default:
      throw throwAssertNever(consoleRole);
  }
};

/** The system role a console role copies, if it copies one. */
export const consoleSystemRoles = ({
  consoleRole,
}: ConsolePolicy): readonly string[] => {
  switch (consoleRole) {
    case "sql-console-readonly":
    case "sql-console-admin":
      return [];
    case "service-reader":
    case "service-admin":
      return [SYSTEM_SERVICE_ROLES[consoleRole]];
    default:
      throw throwAssertNever(consoleRole);
  }
};

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceHierarchyRouter(t, spec, ({ logger }: ConnectorContext) => ({
    ...newCommonClickHousePrimitives(logger),
    ...newPolicyPrimitives(logger, toConsolePolicies, consoleSystemRoles),
  }));
